package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/proto/waMmsRetry"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

const (
	autoDownloadMaxBytes = 100 << 20
	mediaRetryTimeout    = 45 * time.Second
	downloadTimeout      = 4 * time.Minute
)

type MediaInfo struct {
	Type          string
	Filename      string
	URL           string
	DirectPath    string
	Mimetype      string
	MediaKey      []byte
	FileSHA256    []byte
	FileEncSHA256 []byte
	FileLength    uint64
}

type storedMedia struct {
	MediaInfo
	Sender    string
	SenderJID string
	IsFromMe  bool
	LocalPath string
}

func migrateMessagesTable(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(messages)")
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()

	for _, col := range []string{"direct_path", "mimetype", "sender_jid", "local_path"} {
		if existing[col] {
			continue
		}
		if _, err := db.Exec(fmt.Sprintf("ALTER TABLE messages ADD COLUMN %s TEXT", col)); err != nil {
			return fmt.Errorf("add column %s: %w", col, err)
		}
		fmt.Printf("Migrated messages table: added column %s\n", col)
	}
	return nil
}

// unwrapMessage strips container messages that history sync delivers as-is
// (live events.Message is already unwrapped by whatsmeow).
func unwrapMessage(msg *waProto.Message) *waProto.Message {
	for i := 0; i < 5 && msg != nil; i++ {
		switch {
		case msg.GetEphemeralMessage().GetMessage() != nil:
			msg = msg.GetEphemeralMessage().GetMessage()
		case msg.GetViewOnceMessage().GetMessage() != nil:
			msg = msg.GetViewOnceMessage().GetMessage()
		case msg.GetViewOnceMessageV2().GetMessage() != nil:
			msg = msg.GetViewOnceMessageV2().GetMessage()
		case msg.GetViewOnceMessageV2Extension().GetMessage() != nil:
			msg = msg.GetViewOnceMessageV2Extension().GetMessage()
		case msg.GetDocumentWithCaptionMessage().GetMessage() != nil:
			msg = msg.GetDocumentWithCaptionMessage().GetMessage()
		default:
			return msg
		}
	}
	return msg
}

func extForMime(mimetype, fallback string) string {
	base := strings.TrimSpace(strings.SplitN(mimetype, ";", 2)[0])
	switch base {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	case "video/mp4":
		return ".mp4"
	case "audio/ogg":
		return ".ogg"
	case "audio/mp4", "audio/aac":
		return ".m4a"
	case "audio/mpeg":
		return ".mp3"
	case "application/pdf":
		return ".pdf"
	}
	if base != "" {
		if exts, err := mime.ExtensionsByType(base); err == nil && len(exts) > 0 {
			return exts[0]
		}
	}
	return fallback
}

func sanitizeFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == ':' {
			return '_'
		}
		return r
	}, name)
	if name == "." || name == ".." || name == "/" {
		return ""
	}
	return name
}

// extractMediaInfo builds a per-message unique filename (message ID in the name) so
// several photos received in the same second no longer collide on disk.
func extractMediaInfo(msg *waProto.Message, msgID string, ts time.Time) MediaInfo {
	msg = unwrapMessage(msg)
	if msg == nil {
		return MediaInfo{}
	}
	if ts.IsZero() || ts.Unix() == 0 {
		ts = time.Now()
	}
	stamp := ts.Format("20060102_150405")
	if msgID != "" {
		stamp += "_" + msgID
	}

	if img := msg.GetImageMessage(); img != nil {
		return MediaInfo{"image", "image_" + stamp + extForMime(img.GetMimetype(), ".jpg"), img.GetURL(), img.GetDirectPath(), img.GetMimetype(),
			img.GetMediaKey(), img.GetFileSHA256(), img.GetFileEncSHA256(), img.GetFileLength()}
	}
	if vid := msg.GetVideoMessage(); vid != nil {
		return MediaInfo{"video", "video_" + stamp + extForMime(vid.GetMimetype(), ".mp4"), vid.GetURL(), vid.GetDirectPath(), vid.GetMimetype(),
			vid.GetMediaKey(), vid.GetFileSHA256(), vid.GetFileEncSHA256(), vid.GetFileLength()}
	}
	if aud := msg.GetAudioMessage(); aud != nil {
		return MediaInfo{"audio", "audio_" + stamp + extForMime(aud.GetMimetype(), ".ogg"), aud.GetURL(), aud.GetDirectPath(), aud.GetMimetype(),
			aud.GetMediaKey(), aud.GetFileSHA256(), aud.GetFileEncSHA256(), aud.GetFileLength()}
	}
	if doc := msg.GetDocumentMessage(); doc != nil {
		filename := sanitizeFilename(doc.GetFileName())
		if filename == "" {
			filename = "document_" + stamp + extForMime(doc.GetMimetype(), "")
		}
		return MediaInfo{"document", filename, doc.GetURL(), doc.GetDirectPath(), doc.GetMimetype(),
			doc.GetMediaKey(), doc.GetFileSHA256(), doc.GetFileEncSHA256(), doc.GetFileLength()}
	}
	return MediaInfo{}
}

// directPathFromURL is the fallback for rows stored before direct_path existed.
// The signed query (oh/oe/_nc_sid) must be kept: without it the CDN answers 403.
func directPathFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return ""
	}
	if u.RawQuery == "" {
		return u.EscapedPath()
	}
	return u.EscapedPath() + "?" + u.RawQuery
}

func whatsmeowMediaType(t string) (whatsmeow.MediaType, error) {
	switch t {
	case "image":
		return whatsmeow.MediaImage, nil
	case "video":
		return whatsmeow.MediaVideo, nil
	case "audio":
		return whatsmeow.MediaAudio, nil
	case "document":
		return whatsmeow.MediaDocument, nil
	}
	return "", fmt.Errorf("unsupported media type: %s", t)
}

func (store *MessageStore) getStoredMedia(id, chatJID string) (*storedMedia, error) {
	var sm storedMedia
	var mediaType, filename, rawURL, directPath, mimetype, sender, senderJID, localPath sql.NullString
	var fileLength sql.NullInt64
	var isFromMe sql.NullBool
	err := store.db.QueryRow(
		`SELECT media_type, filename, url, direct_path, mimetype, media_key, file_sha256, file_enc_sha256, file_length,
			sender, sender_jid, is_from_me, local_path
		FROM messages WHERE id = ? AND chat_jid = ?`,
		id, chatJID,
	).Scan(&mediaType, &filename, &rawURL, &directPath, &mimetype, &sm.MediaKey, &sm.FileSHA256, &sm.FileEncSHA256, &fileLength,
		&sender, &senderJID, &isFromMe, &localPath)
	if err != nil {
		return nil, err
	}
	sm.Type, sm.Filename, sm.URL, sm.DirectPath, sm.Mimetype = mediaType.String, filename.String, rawURL.String, directPath.String, mimetype.String
	sm.FileLength = uint64(fileLength.Int64)
	sm.Sender, sm.SenderJID, sm.IsFromMe, sm.LocalPath = sender.String, senderJID.String, isFromMe.Bool, localPath.String
	return &sm, nil
}

func (store *MessageStore) setLocalPath(id, chatJID, path string) error {
	_, err := store.db.Exec("UPDATE messages SET local_path = ? WHERE id = ? AND chat_jid = ?", path, id, chatJID)
	return err
}

func (store *MessageStore) setDirectPath(id, chatJID, directPath string) error {
	_, err := store.db.Exec("UPDATE messages SET direct_path = ? WHERE id = ? AND chat_jid = ?", directPath, id, chatJID)
	return err
}

var (
	mediaRetryMu      sync.Mutex
	mediaRetryWaiters = map[string]chan *events.MediaRetry{}
	downloadLocks     sync.Map
	autoDownloadSem   = make(chan struct{}, 3)
)

// handleMediaRetry runs inside the whatsmeow event loop, so it must never block.
func handleMediaRetry(evt *events.MediaRetry) {
	mediaRetryMu.Lock()
	ch := mediaRetryWaiters[string(evt.MessageID)]
	mediaRetryMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- evt:
	default:
	}
}

func resolveSenderJID(client *whatsmeow.Client, sm *storedMedia) types.JID {
	for _, candidate := range []string{sm.SenderJID, sm.Sender} {
		if strings.Contains(candidate, "@") {
			if jid, err := types.ParseJID(candidate); err == nil {
				return jid
			}
		}
	}
	lid := types.NewJID(sm.Sender, types.HiddenUserServer)
	if pn, err := client.Store.LIDs.GetPNForLID(context.Background(), lid); err == nil && !pn.IsEmpty() {
		return lid
	}
	return types.NewJID(sm.Sender, types.DefaultUserServer)
}

// requestMediaRetry asks our own phone to re-upload the media and returns the fresh direct path.
// This is a receipt to our own account, nothing is sent to the contact.
func requestMediaRetry(ctx context.Context, client *whatsmeow.Client, sm *storedMedia, msgID, chatJID string) (string, error) {
	chat, err := types.ParseJID(chatJID)
	if err != nil {
		return "", fmt.Errorf("invalid chat jid: %w", err)
	}
	info := &types.MessageInfo{
		ID: types.MessageID(msgID),
		MessageSource: types.MessageSource{
			Chat:     chat,
			IsFromMe: sm.IsFromMe,
			IsGroup:  chat.Server == types.GroupServer,
		},
	}
	if info.IsGroup {
		info.Sender = resolveSenderJID(client, sm)
	}

	ch := make(chan *events.MediaRetry, 1)
	mediaRetryMu.Lock()
	mediaRetryWaiters[msgID] = ch
	mediaRetryMu.Unlock()
	defer func() {
		mediaRetryMu.Lock()
		delete(mediaRetryWaiters, msgID)
		mediaRetryMu.Unlock()
	}()

	fmt.Printf("Requesting media re-upload for message %s in chat %s\n", msgID, chatJID)
	if err := client.SendMediaRetryReceipt(ctx, info, sm.MediaKey); err != nil {
		return "", fmt.Errorf("failed to send media retry receipt: %w", err)
	}

	select {
	case evt := <-ch:
		notif, err := whatsmeow.DecryptMediaRetryNotification(evt, sm.MediaKey)
		if err != nil {
			return "", err
		}
		if notif.GetResult() != waMmsRetry.MediaRetryNotification_SUCCESS {
			return "", fmt.Errorf("media retry result: %s", notif.GetResult())
		}
		if notif.GetDirectPath() == "" {
			return "", errors.New("media retry returned empty direct path")
		}
		return notif.GetDirectPath(), nil
	case <-time.After(mediaRetryTimeout):
		return "", errors.New("timed out waiting for media retry response (phone offline?)")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func isExpiredMediaError(err error) bool {
	return errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith403) ||
		errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith404) ||
		errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith410)
}

func fetchMedia(ctx context.Context, client *whatsmeow.Client, store *MessageStore, sm *storedMedia, msgID, chatJID string) ([]byte, error) {
	waType, err := whatsmeowMediaType(sm.Type)
	if err != nil {
		return nil, err
	}
	download := func(directPath string) ([]byte, error) {
		data, err := client.DownloadMediaWithPath(ctx, directPath, sm.FileEncSHA256, sm.FileSHA256, sm.MediaKey, waType, "", false)
		if errors.Is(err, whatsmeow.ErrInvalidMediaEncSHA256) || errors.Is(err, whatsmeow.ErrInvalidMediaSHA256) {
			// Seen on 03.11.2026 for ~1 month old photos: after a media retry the phone
			// re-uploads with fresh encryption and the original media key cannot decrypt it.
			return nil, fmt.Errorf("media was re-uploaded with new encryption, original key cannot decrypt it (pull it from the phone instead): %w", err)
		}
		return data, err
	}

	directPath := sm.DirectPath
	if directPath == "" {
		directPath = directPathFromURL(sm.URL)
	}
	var firstErr error
	if directPath != "" {
		data, err := download(directPath)
		if err == nil {
			return data, nil
		}
		if !isExpiredMediaError(err) {
			return nil, err
		}
		firstErr = err
		fmt.Printf("Media download for %s failed (%v), falling back to media retry\n", msgID, err)
	}

	newPath, err := requestMediaRetry(ctx, client, sm, msgID, chatJID)
	if err != nil {
		if firstErr != nil {
			return nil, fmt.Errorf("%v; media retry failed: %w", firstErr, err)
		}
		return nil, fmt.Errorf("media retry failed: %w", err)
	}
	if err := store.setDirectPath(msgID, chatJID, newPath); err != nil {
		fmt.Printf("Warning: failed to store refreshed direct path for %s: %v\n", msgID, err)
	}
	return download(newPath)
}

func fileMatchesSHA256(path string, want []byte) bool {
	if len(want) != 32 {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(data)
	return bytes.Equal(sum[:], want)
}

func chatMediaDir(chatJID string) string {
	return filepath.Join("store", strings.ReplaceAll(chatJID, ":", "_"))
}

// targetPath keeps the original name when free; otherwise appends the message ID.
func targetPath(dir, filename, msgID string) string {
	name := sanitizeFilename(filename)
	if name == "" {
		name = msgID
	}
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return p
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if strings.Contains(base, msgID) {
		return p
	}
	return filepath.Join(dir, base+"_"+msgID+ext)
}

// downloadMedia returns the local path of a message's media, fetching it if needed.
func downloadMedia(client *whatsmeow.Client, messageStore *MessageStore, messageID, chatJID string) (bool, string, string, string, error) {
	lockAny, _ := downloadLocks.LoadOrStore(chatJID+"/"+messageID, &sync.Mutex{})
	lock := lockAny.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	sm, err := messageStore.getStoredMedia(messageID, chatJID)
	if err != nil {
		return false, "", "", "", fmt.Errorf("failed to find message: %v", err)
	}
	if sm.Type == "" {
		return false, "", "", "", fmt.Errorf("not a media message")
	}

	if sm.LocalPath != "" {
		if _, err := os.Stat(sm.LocalPath); err == nil {
			return true, sm.Type, filepath.Base(sm.LocalPath), sm.LocalPath, nil
		}
	}

	chatDir := chatMediaDir(chatJID)
	if err := os.MkdirAll(chatDir, 0755); err != nil {
		return false, "", "", "", fmt.Errorf("failed to create chat directory: %v", err)
	}

	// Files saved by older bridge versions: only trust them if the hash matches,
	// since several messages could share one filename back then.
	if legacy := filepath.Join(chatDir, sanitizeFilename(sm.Filename)); fileMatchesSHA256(legacy, sm.FileSHA256) {
		if abs, err := filepath.Abs(legacy); err == nil {
			_ = messageStore.setLocalPath(messageID, chatJID, abs)
			return true, sm.Type, filepath.Base(abs), abs, nil
		}
	}

	if len(sm.MediaKey) == 0 || len(sm.FileSHA256) == 0 || len(sm.FileEncSHA256) == 0 {
		return false, "", "", "", fmt.Errorf("incomplete media information for download")
	}
	if !client.IsConnected() {
		return false, "", "", "", fmt.Errorf("not connected to WhatsApp")
	}

	fmt.Printf("Downloading %s for message %s in chat %s...\n", sm.Type, messageID, chatJID)
	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	data, err := fetchMedia(ctx, client, messageStore, sm, messageID, chatJID)
	if err != nil {
		return false, "", "", "", fmt.Errorf("failed to download media: %v", err)
	}

	localPath := targetPath(chatDir, sm.Filename, messageID)
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return false, "", "", "", fmt.Errorf("failed to get absolute path: %v", err)
	}
	tmp := absPath + ".part"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return false, "", "", "", fmt.Errorf("failed to save media file: %v", err)
	}
	if err := os.Rename(tmp, absPath); err != nil {
		os.Remove(tmp)
		return false, "", "", "", fmt.Errorf("failed to save media file: %v", err)
	}
	if err := messageStore.setLocalPath(messageID, chatJID, absPath); err != nil {
		fmt.Printf("Warning: failed to record local path for %s: %v\n", messageID, err)
	}

	fmt.Printf("Saved %s media to %s (%d bytes)\n", sm.Type, absPath, len(data))
	return true, sm.Type, filepath.Base(absPath), absPath, nil
}

func shouldAutoDownload(chatJID string, media MediaInfo) bool {
	if chatJID == "status@broadcast" || media.Type == "" {
		return false
	}
	return media.FileLength <= autoDownloadMaxBytes
}

func autoDownloadMedia(client *whatsmeow.Client, messageStore *MessageStore, messageID, chatJID string) {
	autoDownloadSem <- struct{}{}
	defer func() { <-autoDownloadSem }()
	if _, _, _, _, err := downloadMedia(client, messageStore, messageID, chatJID); err != nil {
		fmt.Printf("Auto-download failed for %s in %s: %v\n", messageID, chatJID, err)
	}
}

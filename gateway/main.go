package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/websocket/v2"
	_ "github.com/mattn/go-sqlite3"
)

// ── Config ────────────────────────────────────────────
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

var (
	DETECTION_URL = getEnv("DETECTION_URL", "http://localhost:8000")
	PORT          = getEnv("PORT", "9000")
	DB_PATH       = getEnv("DB_PATH", "filesense.db")
	BASE_DIR      = getEnv("BASE_DIR", "")
)

// ── Structs ───────────────────────────────────────────
type DetectionRequest struct {
	Query      string `json:"query"`
	SourceIP   string `json:"source_ip"`
	SourceHost string `json:"source_host"`
}

type XAIToken struct {
	Token     string  `json:"token"`
	Shap      float64 `json:"shap"`
	Direction string  `json:"direction"`
}

type MitreInfo struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
}

type DetectionResult struct {
	Query          string     `json:"query"`
	Timestamp      string     `json:"timestamp"`
	IsSQLi         bool       `json:"is_sqli"`
	Confidence     float64    `json:"confidence"`
	Label          string     `json:"label"`
	AttackType     string     `json:"attack_type"`
	Severity       string     `json:"severity"`
	Mitre          *MitreInfo `json:"mitre"`
	XAITokens      []XAIToken `json:"xai_tokens"`
	LLMExplanation string     `json:"llm_explanation"`
	SourceIP       string     `json:"source_ip"`
	SourceHost     string     `json:"source_host"`
}

type FeedbackRequest struct {
	Name        string         `json:"name"`
	Email       string         `json:"email"`
	Role        string         `json:"role"`
	Positive    string         `json:"positive"`
	Negative    string         `json:"negative"`
	Suggestions string         `json:"suggestions"`
	Ratings     map[string]int `json:"ratings"`
}

// ── HTTP client with timeout for detection calls ──────
var detectionClient = &http.Client{Timeout: 120 * time.Second}

// ── Call Python detection server ──────────────────────
func callDetection(query, sourceIP, sourceHost string) (*DetectionResult, error) {
	reqBody := DetectionRequest{
		Query:      query,
		SourceIP:   sourceIP,
		SourceHost: sourceHost,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := detectionClient.Post(
		DETECTION_URL+"/detect",
		"application/json",
		bytes.NewBuffer(bodyBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("detection server unavailable: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result DetectionResult
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// ── WebSocket clients ─────────────────────────────────
var (
	clients = make(map[*websocket.Conn]bool)
	mu      sync.Mutex
)

func broadcast(result *DetectionResult) {
	mu.Lock()
	defer mu.Unlock()

	data, err := json.Marshal(result)
	if err != nil {
		log.Printf("broadcast error: %v", err)
		return
	}

	for client := range clients {
		err := client.WriteMessage(1, data)
		if err != nil {
			log.Printf("websocket write error: %v", err)
			client.Close()
			delete(clients, client)
		}
	}
}

// ── Simulate process management ───────────────────────
var (
	simGenCmd   *exec.Cmd
	simAgentCmd *exec.Cmd
	simMu       sync.Mutex
	simRunning  bool
)

func resolveBaseDir() string {
	if BASE_DIR != "" {
		return BASE_DIR
	}
	return "."
}

func startSimulation() error {
	simMu.Lock()
	defer simMu.Unlock()

	if simRunning {
		return fmt.Errorf("simulation already running")
	}

	logPath := "/tmp/mysql_general.log"
	baseDir := resolveBaseDir()

	genPath := baseDir + "/tests/generate_log.py"
	if _, err := os.Stat(genPath); err != nil {
		return fmt.Errorf("generate_log.py not found at %s — set BASE_DIR env var", genPath)
	}

	simGenCmd = exec.Command("python3", genPath, "-o", logPath, "--speed", "fast", "--sqli-ratio", "0.3")
	simGenCmd.Stdout = os.Stdout
	simGenCmd.Stderr = os.Stderr
	if err := simGenCmd.Start(); err != nil {
		return fmt.Errorf("failed to start log generator: %w", err)
	}
	log.Printf("🚀 Log generator started (PID %d)", simGenCmd.Process.Pid)

	time.Sleep(2 * time.Second)

	agentDir := baseDir + "/agent"
	agentBin := agentDir + "/agent"

	if _, err := os.Stat(agentBin); err == nil {
		simAgentCmd = exec.Command(agentBin, "-file", logPath)
	} else {
		simAgentCmd = exec.Command("go", "run", "main.go", "-file", logPath)
		simAgentCmd.Dir = agentDir
	}
	simAgentCmd.Stdout = os.Stdout
	simAgentCmd.Stderr = os.Stderr
	if err := simAgentCmd.Start(); err != nil {
		if simGenCmd.Process != nil {
			simGenCmd.Process.Kill()
			simGenCmd.Wait()
		}
		return fmt.Errorf("failed to start agent: %w", err)
	}
	log.Printf("🚀 Agent started (PID %d)", simAgentCmd.Process.Pid)

	simRunning = true

	go func() {
		if simGenCmd.Process != nil {
			simGenCmd.Wait()
		}
		simMu.Lock()
		defer simMu.Unlock()
		if simRunning {
			log.Println("⚠ Log generator exited unexpectedly")
			if simAgentCmd != nil && simAgentCmd.Process != nil {
				simAgentCmd.Process.Kill()
				simAgentCmd.Wait()
			}
			simRunning = false
		}
	}()

	return nil
}

func stopSimulation() {
	simMu.Lock()
	defer simMu.Unlock()

	if !simRunning {
		return
	}

	if simAgentCmd != nil && simAgentCmd.Process != nil {
		simAgentCmd.Process.Kill()
		simAgentCmd.Wait()
		log.Println("🛑 Agent stopped")
	}

	if simGenCmd != nil && simGenCmd.Process != nil {
		simGenCmd.Process.Kill()
		simGenCmd.Wait()
		log.Println("🛑 Log generator stopped")
	}

	simRunning = false
}

func isSimulationRunning() bool {
	simMu.Lock()
	defer simMu.Unlock()
	return simRunning
}

// ── Hardcoded sender credentials ──────────────────────
const (
	SMTP_USER = "querysenseq@gmail.com"
	SMTP_PASS = "golh xtlj qiii mvgn"
)

// ── Send email alert ──────────────────────────────────
func sendEmailAlert(result *DetectionResult) {
	alertEmailRaw := getConfig("alert_email")
	if alertEmailRaw == "" {
		log.Println("No alert recipients configured — skipping email")
		return
	}

	recipients := []string{}
	for _, e := range strings.Split(alertEmailRaw, ",") {
		trimmed := strings.TrimSpace(e)
		if trimmed != "" {
			recipients = append(recipients, trimmed)
		}
	}
	if len(recipients) == 0 {
		log.Println("No valid recipients — skipping email")
		return
	}

	subject := fmt.Sprintf("🚨 SQLi Alert — %s — %s — %.1f%%%%",
		result.SourceIP, result.AttackType, result.Confidence)

	sevColor := "#ff4757"
	switch strings.ToLower(result.Severity) {
	case "high":
		sevColor = "#ff7e30"
	case "medium":
		sevColor = "#ffc300"
	case "low", "normal":
		sevColor = "#2ed573"
	}

	mitreTechnique := "N/A"
	mitreName := "N/A"
	mitreTactic := "N/A"
	if result.Mitre != nil {
		mitreTechnique = result.Mitre.Technique
		mitreName = result.Mitre.Name
		mitreTactic = result.Mitre.Tactic
	}

	shapRows := ""
	for i, t := range result.XAITokens {
		if i >= 5 {
			break
		}
		barWidth := int(t.Shap * 100)
		if barWidth > 100 {
			barWidth = 100
		}
		barColor := "#ff4757"
		if t.Direction == "normal" {
			barColor = "#2ed573"
		}
		shapRows += fmt.Sprintf(`<tr>
			<td style="padding:6px 10px;font-family:'Courier New',monospace;font-size:12px;color:#90afc8;background:#151e28;border-radius:3px;">%s</td>
			<td style="padding:6px 10px;"><div style="background:#151e28;border-radius:4px;height:8px;width:100%%;"><div style="background:%s;border-radius:4px;height:8px;width:%d%%;"></div></div></td>
			<td style="padding:6px 10px;font-family:'Courier New',monospace;font-size:11px;color:%s;text-align:right;">%.4f</td>
		</tr>`, t.Token, barColor, barWidth, barColor, t.Shap)
	}

	attackDisplay := strings.ToUpper(strings.ReplaceAll(result.AttackType, "_", " "))

	body := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0e13;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%%%%" cellpadding="0" cellspacing="0" style="background:#0a0e13;padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:12px;overflow:hidden;border:1px solid #1e2d40;">
  <tr><td style="background:#111820;padding:18px 24px;border-bottom:1px solid #1e2d40;">
    <table width="100%%%%" cellpadding="0" cellspacing="0"><tr>
      <td><span style="font-size:15px;font-weight:700;color:#dce8f4;">🛡 Query<span style="color:#3d8ef5;">Guard</span></span></td>
      <td style="text-align:right;"><span style="font-size:11px;color:#ff4757;background:rgba(255,71,87,0.08);border:1px solid rgba(255,71,87,0.2);padding:4px 10px;border-radius:20px;">● ALERT</span></td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:24px 24px 0;">
    <div style="background:rgba(255,71,87,0.06);border:1px solid %s;border-radius:8px;border-left:4px solid %s;padding:16px 20px;">
      <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#526b85;margin-bottom:6px;">Detection Result</div>
      <div style="font-size:20px;font-weight:700;color:%s;">⚠ %s</div>
      <div style="margin-top:10px;font-family:'Courier New',monospace;font-size:18px;font-weight:600;color:%s;">%.1f%%%% confidence</div>
    </div>
  </td></tr>
  <tr><td style="padding:16px 24px 0;">
    <table width="100%%%%" cellpadding="0" cellspacing="8"><tr>
      <td width="50%%%%" valign="top" style="background:#151e28;border:1px solid #1e2d40;border-radius:7px;padding:14px;">
        <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#526b85;margin-bottom:10px;">Threat Intel</div>
        <table width="100%%%%" cellpadding="0" cellspacing="0">
          <tr><td style="font-size:12px;color:#526b85;padding:4px 0;">Severity</td><td style="font-family:'Courier New',monospace;font-size:11px;color:%s;text-align:right;padding:4px 0;">%s</td></tr>
          <tr><td style="font-size:12px;color:#526b85;padding:4px 0;">Type</td><td style="font-family:'Courier New',monospace;font-size:11px;color:#dce8f4;text-align:right;padding:4px 0;">%s</td></tr>
          <tr><td style="font-size:12px;color:#526b85;padding:4px 0;">MITRE</td><td style="font-family:'Courier New',monospace;font-size:11px;color:#a78bfa;text-align:right;padding:4px 0;">%s</td></tr>
        </table>
      </td>
      <td width="50%%%%" valign="top" style="background:#151e28;border:1px solid #1e2d40;border-radius:7px;padding:14px;">
        <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#526b85;margin-bottom:10px;">Source</div>
        <table width="100%%%%" cellpadding="0" cellspacing="0">
          <tr><td style="font-size:12px;color:#526b85;padding:4px 0;">IP</td><td style="font-family:'Courier New',monospace;font-size:11px;color:#3d8ef5;text-align:right;padding:4px 0;">%s</td></tr>
          <tr><td style="font-size:12px;color:#526b85;padding:4px 0;">Host</td><td style="font-family:'Courier New',monospace;font-size:11px;color:#dce8f4;text-align:right;padding:4px 0;">%s</td></tr>
          <tr><td style="font-size:12px;color:#526b85;padding:4px 0;">Time</td><td style="font-family:'Courier New',monospace;font-size:11px;color:#dce8f4;text-align:right;padding:4px 0;">%s</td></tr>
        </table>
      </td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:16px 24px 0;">
    <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#526b85;margin-bottom:10px;">Detected Query</div>
    <div style="background:#0a0e13;border:1px solid #1e2d40;border-left:3px solid #ff4757;border-radius:0 6px 6px 0;padding:12px 14px;font-family:'Courier New',monospace;font-size:12px;color:#f0c060;word-break:break-all;line-height:1.6;">%s</div>
  </td></tr>
  <tr><td style="padding:16px 24px 0;">
    <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#526b85;margin-bottom:10px;">MITRE ATT&CK</div>
    <span style="display:inline-block;background:rgba(167,139,250,0.1);border:1px solid rgba(167,139,250,0.25);color:#a78bfa;padding:5px 10px;border-radius:4px;font-family:'Courier New',monospace;font-size:11px;margin-right:6px;">🗡 %s</span>
    <span style="display:inline-block;background:rgba(167,139,250,0.1);border:1px solid rgba(167,139,250,0.25);color:#a78bfa;padding:5px 10px;border-radius:4px;font-family:'Courier New',monospace;font-size:11px;margin-right:6px;">📋 %s</span>
    <span style="display:inline-block;background:rgba(167,139,250,0.1);border:1px solid rgba(167,139,250,0.25);color:#a78bfa;padding:5px 10px;border-radius:4px;font-family:'Courier New',monospace;font-size:11px;">🎯 %s</span>
  </td></tr>
  <tr><td style="padding:16px 24px 0;">
    <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#526b85;margin-bottom:10px;">SHAP Explainability</div>
    <table width="100%%%%" cellpadding="0" cellspacing="0">%s</table>
  </td></tr>
  <tr><td style="padding:16px 24px 0;">
    <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#526b85;margin-bottom:10px;">LLM Security Analysis</div>
    <div style="background:#151e28;border:1px solid #1e2d40;border-radius:7px;padding:14px;font-size:12px;line-height:1.8;color:#90afc8;">%s</div>
  </td></tr>
  <tr><td style="padding:24px;text-align:center;border-top:1px solid #1e2d40;margin-top:16px;">
    <div style="font-size:11px;color:#526b85;">QueryGuard Detection System v3.0 — ML + XAI + LLM</div>
  </td></tr>
</table>
</td></tr></table>
</body></html>`,
		sevColor, sevColor,
		sevColor, attackDisplay,
		sevColor, result.Confidence,
		sevColor, strings.ToUpper(result.Severity),
		strings.ReplaceAll(result.AttackType, "_", " "),
		mitreTechnique,
		result.SourceIP, result.SourceHost, result.Timestamp,
		result.Query,
		mitreTechnique, mitreName, mitreTactic,
		shapRows,
		result.LLMExplanation,
	)

	toHeader := strings.Join(recipients, ", ")
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		SMTP_USER, toHeader, subject, body)

	auth := smtp.PlainAuth("", SMTP_USER, SMTP_PASS, "smtp.gmail.com")
	err := smtp.SendMail("smtp.gmail.com:587", auth, SMTP_USER, recipients, []byte(msg))
	if err != nil {
		log.Printf("email alert failed: %v", err)
	} else {
		log.Printf("📧 Email alert sent to %s", toHeader)
	}
}

// ── Send feedback email ───────────────────────────────
func sendFeedbackEmail(fb FeedbackRequest) error {
	recipient := "ravindu.20200642@iit.ac.lk"
	subject := fmt.Sprintf("QueryGuard Feedback — %s (%s)", fb.Name, fb.Role)

	ratingsHTML := ""
	for category, score := range fb.Ratings {
		stars := ""
		for i := 1; i <= 5; i++ {
			if i <= score {
				stars += "★"
			} else {
				stars += "☆"
			}
		}
		ratingsHTML += fmt.Sprintf(`<tr>
			<td style="padding:6px 10px;font-size:13px;color:#90afc8;">%s</td>
			<td style="padding:6px 10px;font-size:16px;color:#ffc300;letter-spacing:2px;">%s</td>
			<td style="padding:6px 10px;font-size:13px;color:#dce8f4;font-weight:600;">%d/5</td>
		</tr>`, strings.Title(strings.ReplaceAll(category, "_", " ")), stars, score)
	}

	positive := fb.Positive
	if positive == "" {
		positive = "<em style='color:#526b85'>No response</em>"
	}
	negative := fb.Negative
	if negative == "" {
		negative = "<em style='color:#526b85'>No response</em>"
	}
	suggestions := fb.Suggestions
	if suggestions == "" {
		suggestions = "<em style='color:#526b85'>No response</em>"
	}

	body := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0e13;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%%%%" cellpadding="0" cellspacing="0" style="background:#0a0e13;padding:24px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:12px;overflow:hidden;border:1px solid #1e2d40;">
  <tr><td style="background:#111820;padding:18px 24px;border-bottom:1px solid #1e2d40;">
    <span style="font-size:15px;font-weight:700;color:#dce8f4;">🛡 Query<span style="color:#3d8ef5;">Guard</span> — Feedback</span>
  </td></tr>
  <tr><td style="padding:24px;">
    <div style="background:#151e28;border:1px solid #1e2d40;border-radius:7px;padding:14px;margin-bottom:16px;">
      <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#526b85;margin-bottom:10px;">Reviewer</div>
      <table width="100%%%%" cellpadding="0" cellspacing="0">
        <tr><td style="font-size:12px;color:#526b85;padding:4px 0;">Name</td><td style="font-size:12px;color:#dce8f4;text-align:right;">%s</td></tr>
        <tr><td style="font-size:12px;color:#526b85;padding:4px 0;">Email</td><td style="font-size:12px;color:#3d8ef5;text-align:right;">%s</td></tr>
        <tr><td style="font-size:12px;color:#526b85;padding:4px 0;">Role</td><td style="font-size:12px;color:#dce8f4;text-align:right;">%s</td></tr>
      </table>
    </div>
    <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#526b85;margin-bottom:10px;">Ratings</div>
    <table width="100%%%%" cellpadding="0" cellspacing="0" style="background:#151e28;border:1px solid #1e2d40;border-radius:7px;margin-bottom:16px;">%s</table>
    <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#2ed573;margin-bottom:8px;">What Worked Well</div>
    <div style="background:#151e28;border:1px solid #1e2d40;border-left:3px solid #2ed573;border-radius:0 6px 6px 0;padding:12px;font-size:12px;color:#90afc8;line-height:1.7;margin-bottom:16px;">%s</div>
    <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#ff4757;margin-bottom:8px;">Areas for Improvement</div>
    <div style="background:#151e28;border:1px solid #1e2d40;border-left:3px solid #ff4757;border-radius:0 6px 6px 0;padding:12px;font-size:12px;color:#90afc8;line-height:1.7;margin-bottom:16px;">%s</div>
    <div style="font-size:10px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#3d8ef5;margin-bottom:8px;">Suggestions</div>
    <div style="background:#151e28;border:1px solid #1e2d40;border-left:3px solid #3d8ef5;border-radius:0 6px 6px 0;padding:12px;font-size:12px;color:#90afc8;line-height:1.7;">%s</div>
  </td></tr>
  <tr><td style="padding:16px 24px;text-align:center;border-top:1px solid #1e2d40;">
    <div style="font-size:11px;color:#526b85;">QueryGuard v3.0 — Feedback System</div>
  </td></tr>
</table>
</td></tr></table>
</body></html>`,
		fb.Name, fb.Email, fb.Role,
		ratingsHTML,
		positive, negative, suggestions,
	)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		SMTP_USER, recipient, subject, body)

	auth := smtp.PlainAuth("", SMTP_USER, SMTP_PASS, "smtp.gmail.com")
	return smtp.SendMail("smtp.gmail.com:587", auth, SMTP_USER, []string{recipient}, []byte(msg))
}

// ── Routes ────────────────────────────────────────────
func setupRoutes(app *fiber.App) {

	// Serve built dashboard (production mode)
	dashboardPath := "dashboard/dist"
	if _, err := os.Stat(dashboardPath); err == nil {
		log.Println("📦 Serving built dashboard from /dashboard/dist")
		app.Static("/", dashboardPath)
	} else {
		log.Println("⚠ No built dashboard found — run 'npm run build' in dashboard/")
	}

	// Status
	app.Get("/api/status", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "online",
			"service": "QueryGuard Gateway",
			"version": "3.0",
		})
	})

	// Config
	app.Get("/api/config", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"alert_email": getConfig("alert_email"),
			"threshold":   getConfig("threshold"),
		})
	})

	app.Post("/api/config", func(c *fiber.Ctx) error {
		var body map[string]string
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}
		for key, value := range body {
			if err := setConfig(key, value); err != nil {
				return c.Status(500).JSON(fiber.Map{"error": err.Error()})
			}
		}
		log.Println("✅ Config updated")
		return c.JSON(fiber.Map{"status": "saved"})
	})

	// ── Simulate ──────────────────────────────────────
	app.Post("/api/simulate/start", func(c *fiber.Ctx) error {
		if err := startSimulation(); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"status": "started"})
	})

	app.Post("/api/simulate/stop", func(c *fiber.Ctx) error {
		stopSimulation()
		return c.JSON(fiber.Map{"status": "stopped"})
	})

	app.Get("/api/simulate/status", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"running": isSimulationRunning()})
	})

	// ── Feedback ──────────────────────────────────────
	app.Post("/api/feedback", func(c *fiber.Ctx) error {
		var fb FeedbackRequest
		if err := c.BodyParser(&fb); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}
		if fb.Name == "" || fb.Email == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name and email are required"})
		}
		if err := sendFeedbackEmail(fb); err != nil {
			log.Printf("feedback email failed: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": "failed to send feedback"})
		}
		log.Printf("📝 Feedback received from %s (%s)", fb.Name, fb.Email)
		return c.JSON(fiber.Map{"status": "sent"})
	})

	// Ingest — Log Agent posts queries here
	app.Post("/api/ingest", func(c *fiber.Ctx) error {
		var req DetectionRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}
		if req.Query == "" {
			return c.Status(400).JSON(fiber.Map{"error": "query is required"})
		}

		result, err := callDetection(req.Query, req.SourceIP, req.SourceHost)
		if err != nil {
			log.Printf("detection error: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		if err := saveDetection(result); err != nil {
			log.Printf("db error: %v", err)
		}

		go broadcast(result)

		if result.IsSQLi {
			log.Printf("🚨 SQLi from %s: %.1f%%", result.SourceIP, result.Confidence)
			go sendEmailAlert(result)
		} else {
			log.Printf("✅ Normal from %s", result.SourceIP)
		}

		return c.JSON(fiber.Map{
			"status":     "processed",
			"is_sqli":    result.IsSQLi,
			"confidence": result.Confidence,
		})
	})

	// Analyze — manual scan
	app.Post("/api/analyze", func(c *fiber.Ctx) error {
		var req DetectionRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}

		result, err := callDetection(req.Query, req.SourceIP, req.SourceHost)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		if err := saveDetection(result); err != nil {
			log.Printf("db error: %v", err)
		}

		return c.JSON(result)
	})

	// History
	app.Get("/api/history", func(c *fiber.Ctx) error {
		limit := c.QueryInt("limit", 100)
		results, err := getHistory(limit)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"count": len(results), "items": results})
	})

	// Stats
	app.Get("/api/stats", func(c *fiber.Ctx) error {
		stats, err := getStats()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(stats)
	})

	// WebSocket
	app.Get("/api/ws", websocket.New(func(c *websocket.Conn) {
		mu.Lock()
		clients[c] = true
		mu.Unlock()
		log.Printf("Client connected — total: %d", len(clients))

		c.WriteJSON(fiber.Map{"type": "connected", "message": "QueryGuard Gateway v3.0"})

		for {
			_, _, err := c.ReadMessage()
			if err != nil {
				break
			}
		}

		mu.Lock()
		delete(clients, c)
		mu.Unlock()
		log.Printf("Client disconnected — total: %d", len(clients))
	}))

	// SPA fallback for React Router
	if _, err := os.Stat(dashboardPath); err == nil {
		app.Get("/*", func(c *fiber.Ctx) error {
			return c.SendFile(dashboardPath + "/index.html")
		})
	}
}

// ── Database ──────────────────────────────────────────
var db *sql.DB

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", DB_PATH)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS detections (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		query       TEXT,
		timestamp   TEXT,
		is_sqli     INTEGER,
		confidence  REAL,
		attack_type TEXT,
		severity    TEXT,
		source_ip   TEXT,
		mitre       TEXT,
		xai_tokens  TEXT,
		llm         TEXT
	)`)
	if err != nil {
		return fmt.Errorf("failed to create detections table: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS config (
		key   TEXT PRIMARY KEY,
		value TEXT
	)`)
	if err != nil {
		return fmt.Errorf("failed to create config table: %w", err)
	}

	defaults := map[string]string{"alert_email": "", "threshold": "70"}
	for key, value := range defaults {
		db.Exec(`INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)`, key, value)
	}

	log.Println("✅ Database initialized")
	return nil
}

func getConfig(key string) string {
	var value string
	db.QueryRow(`SELECT value FROM config WHERE key = ?`, key).Scan(&value)
	return value
}

func setConfig(key, value string) error {
	_, err := db.Exec(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`, key, value)
	return err
}

func saveDetection(result *DetectionResult) error {
	mitre, _ := json.Marshal(result.Mitre)
	xai, _ := json.Marshal(result.XAITokens)
	_, err := db.Exec(`INSERT INTO detections
		(query, timestamp, is_sqli, confidence, attack_type, severity, source_ip, mitre, xai_tokens, llm)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.Query, result.Timestamp, result.IsSQLi, result.Confidence,
		result.AttackType, result.Severity, result.SourceIP,
		string(mitre), string(xai), result.LLMExplanation,
	)
	return err
}

func getHistory(limit int) ([]DetectionResult, error) {
	rows, err := db.Query(`SELECT query, timestamp, is_sqli, confidence, attack_type,
		severity, source_ip, mitre, xai_tokens, llm
		FROM detections ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []DetectionResult
	for rows.Next() {
		var r DetectionResult
		var isSQLi int
		var mitreStr, xaiStr string
		err := rows.Scan(&r.Query, &r.Timestamp, &isSQLi, &r.Confidence,
			&r.AttackType, &r.Severity, &r.SourceIP, &mitreStr, &xaiStr, &r.LLMExplanation)
		if err != nil {
			continue
		}
		r.IsSQLi = isSQLi == 1
		json.Unmarshal([]byte(mitreStr), &r.Mitre)
		json.Unmarshal([]byte(xaiStr), &r.XAITokens)
		results = append(results, r)
	}
	return results, nil
}

func getStats() (fiber.Map, error) {
	var total, sqli int
	db.QueryRow("SELECT COUNT(*) FROM detections").Scan(&total)
	db.QueryRow("SELECT COUNT(*) FROM detections WHERE is_sqli = 1").Scan(&sqli)
	return fiber.Map{"total": total, "sqli_detected": sqli, "normal": total - sqli}, nil
}

// ── Main ──────────────────────────────────────────────
func main() {
	fmt.Println(`
╔══════════════════════════════════════════╗
║         QueryGuard Gateway v3.0         ║
║    ML + XAI + LLM SQLi Detection        ║
╚══════════════════════════════════════════╝`)

	if err := initDB(); err != nil {
		log.Fatalf("Database error: %v", err)
	}
	defer stopSimulation()

	app := fiber.New(fiber.Config{
		AppName:      "QueryGuard Gateway v3.0",
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	})

	app.Use(logger.New())
	app.Use(cors.New())
	setupRoutes(app)

	log.Printf("Gateway starting on port %s", PORT)
	log.Printf("Detection server: %s", DETECTION_URL)

	if err := app.Listen(":" + PORT); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

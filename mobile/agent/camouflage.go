package agent

import (
	"net"
	"net/http"
	"strconv"
	"time"
)

// From the outside the agent must look like an ordinary idle nginx: anything
// that is not a correctly signed request to a known endpoint gets nginx's own
// 404, and plain HTTP sent to the TLS port gets nginx's own 400. The bodies
// are nginx's defaults so a probe cannot tell this apart from a stock server.

const nginx404Body = "<html>\r\n" +
	"<head><title>404 Not Found</title></head>\r\n" +
	"<body>\r\n" +
	"<center><h1>404 Not Found</h1></center>\r\n" +
	"<hr><center>nginx</center>\r\n" +
	"</body>\r\n" +
	"</html>\r\n"

const nginx400Body = "<html>\r\n" +
	"<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n" +
	"<body>\r\n" +
	"<center><h1>400 Bad Request</h1></center>\r\n" +
	"<center>The plain HTTP request was sent to HTTPS port</center>\r\n" +
	"<hr><center>nginx</center>\r\n" +
	"</body>\r\n" +
	"</html>\r\n"

// writeCamouflage404 emits the byte-for-byte response every rejection shares.
// net/http adds Date and Content-Length; we set Server and Content-Type so the
// whole response matches a stock nginx 404.
func writeCamouflage404(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Server", "nginx")
	h.Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(nginx404Body))
}

// writePlainHTTP400 writes nginx's "plain HTTP to HTTPS port" response directly
// to a raw connection — this case is caught at the TLS layer, before any HTTP
// handler runs, so there is no ResponseWriter.
func writePlainHTTP400(c net.Conn) {
	body := nginx400Body
	resp := "HTTP/1.1 400 Bad Request\r\n" +
		"Server: nginx\r\n" +
		"Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		body
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte(resp))
}

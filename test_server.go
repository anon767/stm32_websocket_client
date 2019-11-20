
import (
    "github.com/gorilla/websocket"
    "log"
    "net/http"
)

// Specify options for gorilla websocket
var upgrader = websocket.Upgrader{
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
    CheckOrigin: func(r *http.Request) bool {
        return true
    },
}

// Create a handler function that calls an upgrade to websocket session using our upgrader parameters
func handler(w http.ResponseWriter, r *http.Request) {
    c, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println(err)
        return
    }
    log.Println("connection established")
    defer c.Close()
    for {
        mt, message, err := c.ReadMessage()
        if err != nil {
                log.Println("read:", err)
                break
        }
        log.Printf("recv: %s", message)
        err = c.WriteMessage(mt, message)
        if err != nil {
                log.Println("write:", err)
                break
        }
    }
}

func main() {

    http.HandleFunc("/", handler)
    log.Printf("Listening for SECURE websocket connections.")
    log.Fatal(http.ListenAndServeTLS(":44330", "cert.pem", "key.pem", nil))

}

from http.server import SimpleHTTPRequestHandler, HTTPServer
import xmlrpc.client


class CustomRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            result = ""
            proxy_a = xmlrpc.client.ServerProxy("http://rpca:50051")
            result += proxy_a.endpoint()
            proxy_b = xmlrpc.client.ServerProxy("http://rpcb:50051")
            result += proxy_b.endpoint()
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(("This is from HTTP-B service. " + result).encode('utf-8'))
        except Exception as e:
            print(e, flush=True)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Error fetching data in HTTP-B service.")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), CustomRequestHandler)
    print("Server running on port 8000...")
    server.serve_forever()

from xmlrpc.server import SimpleXMLRPCServer

def endpoint():
    return "This is from RPC-A service"

server = SimpleXMLRPCServer(("0.0.0.0", 50051))
print("RPC Server listening on port 50051...")
server.register_function(endpoint, "endpoint")
server.serve_forever()
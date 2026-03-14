from flask import Flask, Response, request, jsonify
from mcp_server import mcp

app = Flask(__name__)

# health endpoint
@app.route("/")
def root():
    return jsonify({"status": "running"})


@app.route("/mcp/sse")
def mcp_sse():
    """
    SSE stream endpoint required by MCP clients.
    """

    # validate SSE header
    accept = request.headers.get("Accept", "")
    if "text/event-stream" not in accept:
        return "Invalid Accept header", 400

    def event_stream():
        try:
            # FastMCP provides generator for SSE events
            for event in mcp.sse():
                yield f"event: message\ndata: {event}\n\n"

        except Exception as e:
            yield f"event: error\ndata: {str(e)}\n\n"

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


if __name__ == "__main__":
    # bind to LAN
    app.run(host="0.0.0.0", port=8001, threaded=True)

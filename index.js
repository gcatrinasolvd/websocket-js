const http = require('http');
const crypto = require('crypto');

// Standard server creation
const server = http.createServer((_req, res) => {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end('WebSocket server\n');
});

// We use the upgrade event because we mostly want to "upgrade" the connection from HTTP form
server.on('upgrade', (req, socket) => {

    // We filter any request if it isn't from a websocket 
    if (req.headers['upgrade'] !== 'websocket') {
        socket.end('HTTP/1.1 400 Bad Request');
        return;
    }

    // We extract the key from request header
    const acceptKey = req.headers['sec-websocket-key'];
    // We hash the acceptKey
    const hash = generateAcceptValue(acceptKey);
    const responseHeaders = [
        'HTTP/1.1 101 Web Socket Protocol Handshake',
        'Upgrade: WebSocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Accept: ${hash}`
    ];

    //We format the responseHeaders to a websocket standard and send it to the client 
    socket.write(responseHeaders.join('\r\n') + '\r\n\r\n');

    // Handle the data from the incoming WebScoket data 
    socket.on('data', buffer => {
        console.log('Received message from client:', decodeMessage(buffer));
    });
});

function generateAcceptValue(acceptKey) {
    return crypto.createHash('sha1')
        //The hashing function appends this fixed string (it is from the  RFC 6455 protocol)
        .update(acceptKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', 'binary')
        .digest('base64');
}

// ChatGPT decode function haha. 
function decodeMessage(buffer) {
    const firstByte = buffer.readUInt8(0);
    const secondByte = buffer.readUInt8(1);
    const isMasked = (secondByte & 0x80) === 0x80; // Check if the message is masked (masked is a security rule for websocket)
    let currentOffset = 2; // Start after the first two bytes
    let payloadLength = secondByte & 0x7F; // Length of the payload

    // Adjust for longer payloads
    if (payloadLength === 126) {
        payloadLength = buffer.readUInt16BE(currentOffset);
        currentOffset += 2;
    } else if (payloadLength === 127) {
        // Note: This doesn't handle extremely large payloads (larger than 2^32)
        payloadLength = buffer.readUInt32BE(currentOffset + 4); // Gets the last 4 bytes of the 8 byte extended payload length
        currentOffset += 8;
    }

    // Process masking key if present
    let mask = null;
    if (isMasked) {
        mask = buffer.slice(currentOffset, currentOffset + 4); // Extract the mask
        currentOffset += 4;
    }

    // Extract the payload and unmask if necessary
    const payload = buffer.slice(currentOffset, currentOffset + payloadLength);
    if (isMasked) {
        for (let i = 0; i < payload.length; i++) {
            payload[i] ^= mask[i % 4]; // Apply the mask
        }
    }

    return payload.toString(); // Convert buffer to string
}

server.listen(3000, () => {
    console.log('WebSocket server listening on port 3000');
});

import asyncio
import datetime
import random
import websockets
import logging

class WSClient:
    ws = None
    event = asyncio.Event()
    data = ""
    def __init__(self, ws):
        self.ws=ws
    
    def send(self, data):
        self.data=data;
        self.event.set()

class WSServer:
    _connected = dict()
    async def _handler(ws, path):
        global connected
    
        if(path == "checkin"):
            try:
                hwid = await ws.recv()
                #If the hwid is used elsewhere, disconnect the old instance
                if(hwid in connected):
                    connected[hwid].ws.close()
                    
                #We have the hwid, so register
                connected[hwid] = WSClient(ws)
                print("registered client " + hwid)
                
                #ConnectionClosed Exception breaks loop when client disconnects, send pings if no message to send for 10 seconds
                while(True):
                    try:
                        await asyncio.wait_for(connected[hwid].event.wait(),timeout=10)
                        connected[hwid].event.clear()
                        await ws.send(connected[hwid].data)
                    except asyncio.TimeoutError:
                        await ws.ping()
            except websockets.ConnectionClosed:
                pass
            finally:
                print("Disconnect " + hwid)
                # Unregister, but only if a new websocket wasn't opened
                if (hwid in connected and connected[hwid].ws == ws):
                    del connected[hwid]

    def __init__(self, host='127.0.0.1', port=5678):
        self._host = host
        self._port = port
    
    def has_connection(self, hwid):
        return (hwid in self._connected)

    def succeed(self, hwid):
        if (hwid in self._connected):
            self._connected[hwid].send("Success")
        else:
            pass # log error? raise exception?
    
    def fail(self, hwid):
        if (hwid in self._connected):
            self._connected[hwid].send("Failure")
        else:
            pass # log error? raise exception?
    
    def start(self):
        logger = logging.getLogger('websockets.server')
        logger.setLevel(logging.DEBUG)
        logger.addHandler(logging.StreamHandler())
    
        start_server = websockets.serve(self._handler, self._host, self._port)
    
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()

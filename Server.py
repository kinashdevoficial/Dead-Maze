# -*- coding: utf-8 -*-
import traceback, random, time
# Modules
from modules.__AS3__ import ByteArray
from modules.ParsePackets import ParsePackets # Parse Packets
# Essentials
from twisted.internet import protocol, reactor

# CLient
class DMClient(protocol.Protocol):
    def __init__(self):
        # Packet
        self.packages = ''
        self.lastDataID = 0
        self.authKey = random.randint(0, 2147483647)

        # String
        self.defaultLang = 'br'
        self.playerName = ''
        self.password = ''
        self.currentCaptcha = ''

        # Number
        self.langueID = 0
        self.playerID = 0

        # None
        self.awakeTimer = None

        # Bool
        self.isClosed = False
        self.validatingVersion = False
        self.loggedIn = False

        # Time
        self.CAPTime = time.time()
        self.CMDTime = time.time()

    # On client made connection
    def connectionMade(self):
        # Globals
        self.server = self.factory
        self.parsePackets = ParsePackets(self, self.server)

        # Other
        self.server.sendOutput("A Player connected!")

    # On client lost connection
    def connectionLost(self, reason):
        if self.loggedIn:
            del self.server.clients[self.playerName]

        self.server.sendOutput("A Player disconnected!")

    # On client receive data
    def dataReceived(self, data):
        if data.startswith("<policy-file-request/>"):
            self.transport.write("<cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\"/></cross-domain-policy>")
            self.transport.abortConnection()

        else:
            self.packageParser(data)

    def packageParser(self, packet):
        self.packages += packet

        while self.packages.strip('\x00'):
            # Packages >= 5
            if len(self.packages) >= 5:
                bytesize = 0
                package = ""
                length = 0

                packet2 = ByteArray(self.packages)
                bytesize = packet2.readByte()

                if bytesize == 1:
                    length = packet2.readUnsignedByte()

                elif bytesize == 2:
                    length = packet2.readUnsignedShort()

                elif bytesize == 3:
                    length = self.readThreeUnsignedBytes(packet2)

                else:
                    self.packages = ""

                if length >= 1 and packet2.getLength() >= 3:
                    length += 1

                    if length == packet2.getLength():
                        package = packet2.toByteArray()
                        self.packages = ""

                    elif length > packet2.getLength():
                        break

                    else:
                        package = packet2.toByteArray()[:length]
                        self.packages = packet2.toByteArray()[length:]

                else:
                    self.packages = ""

                if package:

                    if len(package) >= 3:
                        self.parsePacketString(ByteArray(package))

    def parsePacketString(self, packet):
        if self.isClosed:
            return

        ID = packet.readByte()
        C  = packet.readByte()
        CC = packet.readByte()

        if not self.validatingVersion:
            if C == 28 and CC == 1 and not self.isClosed:
                version = packet.readShort()
                ckey = packet.readUTF()

                if ckey != self.server.ckey and version != self.server.version:
                    self.server.sendOutput("[Warning] CKEY or VERSION are invalid:", "Client is using C:{0} - V:{1}".format(ckey, version), "Server is C:{0} - V:{1}".format(self.server.ckey, self.server.version))
                    self.transport.abortConnection()

                else:
                    self.validatingVersion = True
                    self.sendCorrectVersion()

            else:
                self.transport.abortConnection()

        else:
            try:
                self.lastDataID = (self.lastDataID + 1) % 100
                self.lastDataID = ID

                self.parsePackets.parsePacket(ID, C, CC, packet)

            except:
                with open('./errors.log', 'a') as f:
                    traceback.print_exc(file = f)
                    f.write("        END\n")
                    self.server.sendOutput("Server", "Error")

    def readThreeUnsignedBytes(self, bytearray):
        return ((bytearray.readUnsignedByte()) << 16) | ((bytearray.readUnsignedByte()) << 8) | (bytearray.readUnsignedByte())

    def writeThreeUnsignedBytes(self, bytearray, data):
        bytearray.writeUnsignedByte(data >> 16)
        bytearray.writeUnsignedByte(data >> 8)
        bytearray.writeUnsignedByte(data >> 0)
        return bytearray

    def sendPacket(self, tokens, data):
        if self.isClosed:
            return

        packet = ByteArray()

        if type(data) == int:
            packet.writeBytes(''.join(map(chr, tokens)) + chr(data))

        elif not type(data) == list:
            packet.writeBytes(''.join(map(chr, tokens)) + data)

        else:
            packet.writeBytes('\x01' + '\x01')
            packet.writeUTF('\x01'.join(map(str, [''.join(map(chr, tokens))] + data)))

        length = packet.getLength()
        packet2 = ByteArray()

        if length <= 0xFF:
            packet2.writeByte(1)
            packet2.writeUnsignedByte(length)

        elif length <= 0xFFFF:
            packet2.writeByte(2)
            packet2.writeUnsignedShort(length)

        elif length <= 0xFFFFFF:
            packet2.writeBytes(3)
            self.writeThreeUnsignedBytes(packet2, length)

        packet2.writeBytes(packet.toByteArray())
        self.transport.write(packet2.toByteArray())

    def sendCorrectVersion(self):
        packet = ByteArray()
        # Data
        packet.writeInt(len(self.server.clients))
        packet.writeByte(self.lastDataID)
        packet.writeUTF(self.defaultLang)
        packet.writeUTF(self.defaultLang)
        packet.writeInt(self.authKey)
        # Send Data
        self.sendPacket([26, 3], packet.toByteArray())
        # Awake Timer
        self.awakeTimer = reactor.callLater(120, self.transport.abortConnection)

    def startGame(self):
        packet = ByteArray()
        packet.writeInt(1)
        packet.writeUTF(self.playerName)
        packet.writeInt(600000)
        packet.writeByte(3)
        packet.writeInt(self.playerID)
        packet.writeByte(1)
        packet.writeByte(0)
        packet.writeBoolean(False)
        self.sendPacket([26, 2], packet.toByteArray())

    def loginAccount(self, playerName, password):
        self.playerName = playerName
        self.password = password
        self.loggedIn = True
        self.playerID = self.server.lastPlayerCode + 1
        self.server.lastPlayerCode += 1

        self.server.clients[self.playerName] = self
        self.startGame()

    def createAccount(self, playerName, password):
        self.playerName = playerName
        self.password = password
        self.loggedIn = True
        self.playerID = self.server.lastPlayerCode + 1
        self.server.lastPlayerCode += 1

        self.server.clients[self.playerName] = self
        self.startGame()

# Server
class DMServer(protocol.ServerFactory):
    protocol = DMClient

    def __init__(self):
        # Config
        self.ckey = ''
        self.version = 0
        self.config = self.getConfig()
        self.setCkey()
        self.setVersion()

        # Number
        self.lastPlayerCode = 0

        # Dictionary
        self.clients = {}

    def getConfig(self):
        with open('./assets/config/config.json') as f:
            config = eval(f.read())
            f.close()
        return config

    def setCkey(self):
        self.ckey = self.config['Server']['ckey']

    def setVersion(self):
        self.version = self.config['Server']['version']

    def buildCaptchaCode(self):
        with open("./assets/config/captcha.json", "r") as cap:
            captchaList = eval(cap.read())
            CC = ''.join([random.choice(captchaList.keys()) for x in range(4)])
            words = list(CC)
            px = 0
            py = 1
            lines = []
            for count in range(1, 17):
                wc = 1
                values = []
                for word in words:
                    ws = captchaList[word]
                    if count > len(ws):
                        count = len(ws)
                    ws = ws[str(count)]
                    values += ws.split(',')[(1 if wc > 1 else 0):]
                    wc += 1
                lines += [','.join(map(str, values))]
                if px < len(values):
                    px = len(values)
                py += 1
                return [CC, (px + 2), 17, lines]

    # Send Output Console
    def sendOutput(self, *args):
        for arg in args:
            print "        " + str(arg)

        print "\n"

# Main
if __name__ == '__main__':
    # Consts
    PORTS = [443, 44440, 44444, 5555, 6112, 3724]
    VERIFIED = []
    FAILED = []
    SERVER = DMServer()

    # Listen to Port loop
    for PORT in PORTS:
        try:
            reactor.listenTCP(PORT, SERVER)
            VERIFIED.append(PORT)

        except:
            FAILED.append(PORT)

    # Other
    if len(VERIFIED) > 0:
        print """
        - Server online on ports:
            .:%s:.

        `CTRL + C` to stop the server
        """ % ('::'.join(str(port) for port in VERIFIED))
        reactor.run() # Start

    else:
        print """
        - Server offline on ports:
            .:%s:.\n\n
        """ % ('::'.join(str(port) for port in FAILED))

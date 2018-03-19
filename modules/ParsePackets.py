# -*- coding: utf-8 -*-
import time as _time
from .__AS3__ import ByteArray

class ParsePackets:
    def __init__(self, client, server):
        self.client = client
        self.server = server

    def parsePacket(self, ID, C, CC, packet):
        string_packet = packet.toByteArray()
        newdata = [False, '']

        if C == 8:
            if CC == 2:
                self.client.langueID = packet.readShort()
                return

            else:
                newdata[0] = True
                newdata[1] = "C 8"

        if C == 26:
            # Beta Key
            if CC == 14:
                key = packet.readUTF()

                self.server.sendOutput("Player used the key {0}".format(key))

            # Login Account
            elif CC == 8:
                playerName = packet.readUTF()
                password = packet.readUTF()
                url = packet.readUTF()

                self.client.loginAccount(playerName, password)

            # Create Account
            elif CC == 7:
                playerName = packet.readUTF().capitalize()
                password = packet.readUTF()
                url = packet.readUTF()

                self.client.createAccount(playerName, password)

            # Captcha
            elif CC == 20:
                if _time.time() - self.client.CAPTime > 2:
                    self.client.currentCaptcha, px, ly, lines = self.server.buildCaptchaCode()

                    packet = ByteArray()
                    packet.writeShort(px)
                    packet.writeShort(ly)
                    packet.writeShort((px * ly))

                    for line in lines:
                        packet.writeBytes('\x00' * 4)

                        for value in line.split(','):
                            packet.writeUnsignedByte(value)
                            packet.writeBytes('\x00' * 3)

                        packet.writeBytes('\x00' * 4)

                    packet.writeBytes('\x00' * (((px * ly) - (packet.getLength() - 6) / 4) * 4))
                    self.client.sendPacket([26, 20], packet.toByteArray())
                    self.client.CAPTime = _time.time()
                return

            elif CC == 26:
                if self.client.awakeTimer.getTime() - _time.time() < 110.0:
                    self.client.awakeTimer.reset(120)
                return

            else:
                newdata[0] = True
                newdata[1] = "Login"

        elif C == 28:
            # Client OS Info
            if CC == 17:
                lang = packet.readUTF()
                system = packet.readUTF()
                other = packet.readUTF()
                return

            elif CC == 4:
                return

            else:
                newdata[0] = True
                newdata[1] = "C 28"

        else:
            newdata[0] = True
            newdata[1] = "New"

        if newdata[0]:
            self.server.sendOutput("New Data: {0}".format(newdata[1]), "        ID:{0}, C:{1}, CC:{2}".format(ID, C, CC), "        {0}".format(repr(string_packet)))

import time
import volatility.debug as debug
import urlparse
import volatility.addrspace as addrspace
import commands
import re
import struct

class VprobeBridge(object):
    def __init__(self, *argv, **argk):
        self.cmd = "/Users/hfu/gitroot/vprobe-test/run-vprobe.sh -d 1 -c 'memmodel guest64; VMMLoad { for(offset = %s; offset < %s + %s; offset += %s) { printf(\"data=%%016x=data\\n\", getguest(offset)); } }'"
        self.ptn = re.compile(r"data=(.*)=data")
        self.addr_width = 8

    def read(self, offset, length):
        print "VprobeBridge: offset=%x, length=%d" % (offset, length)
        cmd = self.cmd % ("0x%x" % offset, "0x%x" % offset, "%d" % length, "%d" % self.addr_width)
        output = commands.getoutput(cmd)
        l = []
        for line in output.splitlines():
            m = self.ptn.search(line)
            if m:
                print "VprobeBridge: data=%s" % m.group(1)
                l.append(m.group(1))

        r = []
        for x in l:
            _long = long(x, base=16)
            p = struct.pack("L", _long)
            r.extend(struct.unpack("8c", p))

        return "".join(r[:length])

    def get_size(self):
        return 1024 * 1024 * 1024 # 1GB

class VprobeAddressSpace(addrspace.AbstractVirtualAddressSpace):
    """A physical layer address space that provides access via vprobe"""

    order = 100 # first or last, i just want to be the one...

    def __init__(self, base, config, **kargs):
        # not already initiated
        self.as_assert(not isinstance(base, VprobeAddressSpace), 'Already in the base.')

        try:
            (scheme, netloc, path, _, _, _) = urlparse.urlparse(config.LOCATION)
            self.as_assert(scheme == 'vprobe', 'Not a vprobe URN')
            self.bridge = VprobeBridge(path)
        except (AttributeError, ValueError):
            self.as_assert(False, "Unable to parse {0} as a URL".format(config.LOCATION))

        addrspace.AbstractVirtualAddressSpace.__init__(self, base, config, **kargs)

        self.size = self.bridge.get_size()

    def vtop(self, vaddr):
        return NotImplementedError("vtop() is not implemented")

    def translate(self, vaddr):
        # getguest takes a vaddr
        return vaddr

    def read(self, offset, length):
        """Reads a specified size in bytes from the current offset
        """
        return self.bridge.read(offset, length)

    def zread(self, offset, length):
        return self.bridge.read(offset, length)

    def write(self, offset, data):
        raise NotImplementedError("write() is not implemented.")

    def get_address_range(self):
        """Returns the size of the address range"""
        return [0, self.size - 1]

    def get_available_addresses(self):
        """Returns a list of available addresses"""
        raise NotImplementedError("write() is not implemented.")

if __name__ == "__main__":
    bridge = VprobeBridge()
    print bridge.read(0xffffffff818000a0, 32)


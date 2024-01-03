from .exceptions import *
from .structure import *
from crccheck.crc import CrcXmodem
import re

crc_checker = CrcXmodem()


class UnpackerBase(object):
    """
    Helper methods for both stateless and stated unpacking.
    """
    @staticmethod
    def _unpack_header(buffer):
        """
        Attempt to unpack a header from the buffer.
        :param buffer: buffer object.
        :return: Header object if successful, None otherwise.
        """
        if len(buffer) == 0:
            return None
        fmt = Header.fmt(buffer[0])
        if len(buffer) >= struct.calcsize(fmt):
            try:
                header = Header.parse(buffer)
                return header
            except struct.error:
                raise CorruptPacket("Unable to parse header: %s" % buffer)
        else:
            return None

    @staticmethod
    def _unpack_footer(buffer, header):
        """
        Unpack the footer. Parse must be valid.
        :param buffer: buffer object.
        :param header: Header object for current packet.
        :return: Footer object.
        """
        try:
            footer = Footer.parse(buffer, header)
            return footer
        except struct.error:
            raise CorruptPacket("Unable to parse footer: %s" % buffer)

    @staticmethod
    def _next_possible_packet_index(buffer):
        """
        Tries to find the next possible start byte of a packet in a buffer. Typically called after a corruption has been
        detected.
        :param buffer: buffer object.
        :return: Index of next valid start byte. Returns -1 if no valid start bytes are found.
        """
        possible_index = [match.start() for match in list(re.finditer(b'\x02', buffer)) + list(re.finditer(b'\x03', buffer))]
        return sorted(possible_index)

    @staticmethod
    def _consume_after_corruption_detected(buffer):
        """
        Gives the number of bytes in the buffer to consume after a corrupt packet was detected.
        :param buffer: buffer object
        :return: Number of bytes to consume in the buffer.
        """
        next_index = UnpackerBase._next_possible_packet_index(buffer)
        if next_index == -1: # no valid start byte was found
            return len(buffer) # consume entire buffer
        else:
            return next_index # consume up to next index

    @staticmethod
    def _packet_size(header):
        return struct.calcsize(Header.fmt(header.payload_index)) + header.payload_length + struct.calcsize(Footer.fmt())

    @staticmethod
    def _packet_parsable(buffer, header):
        """
        Checks if an entire packet is parsable.
        :param buffer: buffer object
        :param header: Header object
        :return: True if the current packet is parsable, False otherwise.
        """
        frame_size = UnpackerBase._packet_size(header)
        return len(buffer) >= frame_size

    @staticmethod
    def _unpack_payload(buffer, header):
        """
        Unpacks the payload of the packet.
        :param buffer: buffer object
        :param header: Header object
        :return: byte string of the payload
        """
        footer_index = header.payload_index + header.payload_length
        return bytes(buffer[header.payload_index:footer_index])

    @staticmethod
    def _validate_payload(payload, footer):
        """
        Validates the payload using the footer. CorruptPacket is raised if the payload is corrupt or the terminator is
        not correct.
        :param payload: byte string
        :param footer: Footer object
        :return: void
        """
        crc_checker.calc(payload)
        if crc_checker.calc(payload) != footer.crc:
            raise CorruptPacket("Invalid checksum value.")
        if footer.terminator is not Footer.TERMINATOR:
            raise CorruptPacket("Invalid terminator: %u" % footer.terminator)
        return

    @staticmethod
    def _unpack(buffer, header, errors, recovery_mode=False):
        """
        Attempt to parse a packet from the buffer.
        :param buffer: buffer object
        :param errors: specifies error handling scheme. see codec error handling schemes
        :return: (1) Packet if parse was successful, None otherwise, (2) Length consumed of buffer
        """
        indices = UnpackerBase._next_possible_packet_index(buffer)
        for index in indices:
            try:
                ubuffer = buffer[index:]
                # if we were not given a header then try to parse one
                if header is None:
                    header = UnpackerBase._unpack_header(ubuffer)
                if header is None:
                    continue
                # check if a packet is parsable
                if UnpackerBase._packet_parsable(ubuffer, header) is False:
                    continue
                # parse the packet
                payload = UnpackerBase._unpack_payload(ubuffer, header)
                footer = UnpackerBase._unpack_footer(ubuffer, header)
                # validate the payload
                UnpackerBase._validate_payload(payload, footer)
                # clean header as we wont need it again
                consumed = UnpackerBase._packet_size(header)
                header = None
                return payload, index + consumed
            except CorruptPacket as corrupt_packet:
                continue
        return None, 0

    @staticmethod
    def _recovery_recurse(buffer, header, errors, consume_on_not_recovered):
        header = None  # clean header
        next_sb = UnpackerBase._next_possible_packet_index(buffer)
        if next_sb == -1:  # no valid start byte in buffer. consume entire buffer
            if consume_on_not_recovered:
                return None, len(buffer)
            else:
                return None, 0
        else:
            payload, consumed = UnpackerBase._unpack(buffer[next_sb:], header, errors, True)
            if payload is None:
                # failed to recover
                if consume_on_not_recovered:
                    return payload, consumed + next_sb
                else:
                    return payload, consumed
            else:
                # recovery was successful
                return payload, consumed + next_sb



class PackerBase(object):
    """
    Packing is the same for stated and stateless. Therefore its implemented in this base class.
    """
    @staticmethod
    def _pack(payload):
        """
        Packs a payload.
        :param payload: byte string of payload
        :return: byte string of packed packet
        """
        if payload == b'':
            raise InvalidPayload("Empty payload")
        # get header/footer tuples
        header = Header.generate(payload)
        footer = Footer.generate(payload)
        # serialize tuples
        header = struct.pack(Header.fmt(header.payload_index), *header)
        footer = struct.pack(Footer.fmt(), *footer)
        return header + payload + footer


class Stateless(UnpackerBase, PackerBase):
    """
    Statelessly pack and unpack VESC packets.
    """
    @staticmethod
    def unpack(buffer, errors='ignore'):
        """
        Attempt to parse a packet from the buffer.
        :param buffer: buffer object
        :param errors: specifies error handling scheme. see codec error handling schemes
        :return: (1) Packet if parse was successful, None otherwise, (2) Length consumed of buffer
        """
        return Stateless._unpack(buffer, None, errors)

    @staticmethod
    def pack(payload):
        """
        See PackerBase.pack
        """
        return Stateless._pack(payload)

def frame(bytestring):
    return Stateless.pack(bytestring)

def unframe(buffer, errors='ignore'):
    return Stateless.unpack(buffer, errors)

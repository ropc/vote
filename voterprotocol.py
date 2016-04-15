class ProtocolMessages(object):

    REQ_VALIDATION_NUM = b'\x01'

    VALIDATION_NUM = b'\x02'
    UNREGISTERED_VOTER = b'\x03'

    VOTE = b'\x04'
    BALLOT_REQUEST = b'\x05'

    VOTE_SUCCESS = b'\x06'
    BALLOT_RESPONSE = '\x07'
    INVALID_VALIDATION_NUM = '\x08'
    VALIDATION_NUM_ALREADY_USED = '\x09'

    KEEP_ALIVE = b'\x00'
    UNKNOWN_MSG = b'\xff'

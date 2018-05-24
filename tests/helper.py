#-------------------------------------------------------------------------------
# Placeholder State object for testing purposes.


class State(object):
    def __init__(self, student_code='', msg='MAIN ERROR MESSAGE'):
        self.student_code = student_code
        self.tc_debug = True
        self.tc_msg = ''

    def do_test(self, msg):
        raise Exception(msg)


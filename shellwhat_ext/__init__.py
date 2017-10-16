import os
from shellwhat.sct_syntax import state_dec

__version__ = '0.1.0'

def _get_lines_from_file(state, filename):
    '''Return a list of whitespace-stripped lines from a file, or
    fail if the file cannot be found.'''

    try:
        with open(filename, 'r') as stream:
           lines = [x.strip() for x in stream.readlines()]

    except Exception as err:
        state.do_test('Unable to open file {}'.format(filename))

    return lines


@state_dec
def test_compare_file_to_file(state, actualFilename, expectFilename, debug=None):
    '''Check if a file is line-by-line equal to another file (ignoring
    whitespace at the start and end of lines).'''

    actualList = _get_lines_from_file(state, actualFilename)
    expectList = _get_lines_from_file(state, expectFilename)

    actualLen = len(actualList)
    expectLen = len(expectList)
    if actualLen != expectLen:
        msg = 'File {} has wrong length: got {} expected {}'
        msg = msg.format(actualFilename, actualLen, expectLen)
        if debug is not None:
            msg += ' (-( {} )-)'.format(debug)
        state.do_test(msg)

    diffs = []
    for (i, actualLine, expectLine) in zip(range(len(actualList)), actualList, expectList):
        if actualLine != expectLine:
            diffs.append(i+1)

    if diffs:
        msg = 'Line(s) in {} not as expected: {}'
        msg = msg.format(actualFilename, ', '.join([str(x) for x in diffs]))
        if debug is not None:
            msg += ' (-( {} // expect {} // actual {} )-)'.format(debug, str(expectList), str(actualList))
        state.do_test(msg)

    return state # all good


@state_dec
def test_file_perms(state, path, perms, message, debug=None):
    '''Test that something has the required permissions.'''

    if not os.path.exists(path):
        msg = '{} does not exist'.format(path)
        if debug is not None:
            msg += ' (-( {} )-)'.format(debug)
        state.do_test(msg)
    controls = {'r' : os.R_OK, 'w' : os.W_OK, 'x' : os.X_OK}
    flags = 0
    for p in perms:
        flags += controls[p]
    if not os.access(path, flags):
        state.do_test('{} {}'.format(path, message))
    return state


@state_dec
def test_show_student_code(state, msg):
    state.do_test('{}:\n```\n{}\n```\n'.format(msg, state.student_code))

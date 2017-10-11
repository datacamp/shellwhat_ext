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
def test_compare_file_to_file(state, actualFilename, expectFilename):
    '''Check if a file is line-by-line equal to another file (ignoring
    whitespace at the start and end of lines).'''

    expectList = _get_lines_from_file(state, expectFilename)
    actualList = _get_lines_from_file(state, actualFilename)

    actualLen = len(actualList)
    expectLen = len(expectList)
    if actualLen != expectLen:
        msg = 'File {} has wrong length: got {} expected {}'
        state.do_test(msg.format(actualFilename, actualLen, expectLen))

    diffs = []
    for (i, actualLine, expectLine) in zip(range(len(actualList)), actualList, expectList):
        if actualLine != expectLine:
            diffs.append(i+1)

    if diffs:
        msg = 'Line(s) in {} not as expected: {}'
        state.do_test(msg.format(actualFilename, ', '.join([str(x) for x in diffs])))

    return state # all good


@state_dec
def test_file_perms(state, path, perms, message):
    '''Test that something has the required permissions.'''

    controls = {'r' : os.R_OK, 'w' : os.W_OK, 'x' : os.X_OK}
    flags = 0
    for p in perms:
        flags += controls[p]
    if not os.access(path, flags):
        actual = oct(os.stat(path).st_mode & 0x1ff)[-3:]
        state.do_test('{} {} (actual {})'.format(path, message, actual))
    return state

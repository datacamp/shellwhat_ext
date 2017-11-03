import os
import re
from getopt import getopt
from shellwhat.sct_syntax import state_dec

__version__ = '0.1.0'

#-------------------------------------------------------------------------------

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


def _get_lines_from_file(state, filename):
    '''Return a list of whitespace-stripped lines from a file, or
    fail if the file cannot be found.'''

    try:
        with open(filename, 'r') as stream:
           lines = [x.strip() for x in stream.readlines()]

    except Exception as err:
        state.do_test('Unable to open file {}'.format(filename))

    return lines

#-------------------------------------------------------------------------------

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

#-------------------------------------------------------------------------------

@state_dec
def test_output_does_not_contain(state, text, fixed=True, msg='Submission output contains "{}"'):
    '''Test that the output doesn't match.'''

    if fixed:
        if text in state.student_result:
            state.do_test(msg.format(text))

    else:
        pat = re.compile(text)
        if text.search(state.student_result):
            state.do_test(msg.format(text))

    return state

#-------------------------------------------------------------------------------

@state_dec
def test_show_student_code(state, msg):
    state.do_test('{}:\n```\n{}\n```\n'.format(msg, state.student_code))

#-------------------------------------------------------------------------------    

PAT_TYPE = type(re.compile('x'))
PAT_ARGS = re.compile('{}|{}|{}'.format(r'[^"\'\s]+', r"'[^']+'", r'"[^"]+"'))

@state_dec
def test_cmdline(state, pattern, redirect=None, msg='Error'):
    actualCommands, actualRedirect = _cmdline_parse(state)
    _cmdline_match_redirect(state, redirect, actualRedirect)
    _cmdline_match_all_commands(state, pattern, actualCommands)
    return state


def _cmdline_parse(state):
    stripped, redirect = _cmdline_get_redirect(state)
    commands = [_cmdline_parse_command(c.strip()) for c in stripped.strip().split('|')]
    return commands, redirect


def _cmdline_get_redirect(state):

    text = state.student_result

    if '>' not in text:
        return text, None
    if text.count('>') > 1:
        state.do_test('Command line can contain at most one ">"')

    pre, post = [x.strip() for x in text.split('>')]

    if not pre:
        state.do_test('Line cannot start with redirection')
    if not post:
        state.do_test('Dangling ">" at end of line')
    if '|' in post:
        state.do_test('Cannot redirect to something containing a pipe "{}".format(post)')
    if ' ' in post:
        state.do_test('Cannot redirect to something containin spaces "{}"'.format(post))

    return pre, post


def _cmdline_match_redirect(state, pattern, actual):
    if pattern is None:
        if actual:
            state.do_test('Redirect found when none expected "{}"'.format(actual))
    elif isinstance(pattern, str):
        if pattern != actual:
            state.do_test('Pattern "{}" does not match actual "{}"'.format(pattern, actual))
    elif type(pattern) == PAT_TYPE:
        if not pattern.search(actual):
            state.do_test('Regular expression "{}" does not match actual "{}"'.format(pattern.pattern, actual))


def _cmdline_parse_command(text):
    return [_cmdline_strip_quotes(a) for a in PAT_ARGS.findall(text)]


def _cmdline_strip_quotes(val):
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1]
    return val


def _cmdline_match_all_commands(state, pattern, actual):
    if len(pattern) != len(actual):
        state.do_test('Unexpected number of components in command line: expected "{}" found "{}"'.format(len(pattern), len(actual)))
    for (p, a) in zip(pattern, actual):
        _cmdline_match_command(state, p, a)


def _cmdline_match_command(state, pattern, actual):

    # Command.
    assert len(pattern) > 0, 'Pattern must have at least a command name'
    assert len(actual) > 0, 'Command cannot be empty'

    # Disassemble pattern.
    pat_cmd, pat_optstring, pat_filespec, pat_constraints = _cmdline_disassemble_pattern(pattern)
    if pat_cmd != actual[0]:
        state.do_test('Expected command "{}" got "{}"'.format(pat_cmd, actual[0]))

    # No parameters allowed.
    if pat_optstring is None:
        if len(actual) > 1:
            state.do_test('Pattern does not allow parameters but actual command contains some "{}"'.format(actual))
        return state

    # Get actual flags, their arguments, and trailing filenames.
    actual_opts, actual_extras = getopt(actual[1:], pat_optstring)

    # Check trailing filenames both ways.
    _cmdline_check_filenames(state, pat_cmd, pat_filespec, actual_extras)

    # Check constraints.
    _cmdline_check_constraints(state, pat_cmd, pat_constraints, actual_opts)


def _cmdline_disassemble_pattern(pattern):
    cmd, optstring, filespec, constraints = pattern[0], None, None, None
    if len(pattern) > 1:
        optstring = pattern[1]
    if len(pattern) > 2:
        filespec = pattern[2]
    if len(pattern) > 3:
        constraints = pattern[3]
    assert len(pattern) <= 4, 'Pattern can have at most four elements'
    return cmd, optstring, filespec, constraints


def _cmdline_check_filenames(state, cmd, filespec, extras):
    if filespec is None:
        if extras:
            state.do_test('Unexpected trailing filenames "{}" for "{}"'.format(extras, cmd))
    elif isinstance(filespec, str):
        if filespec == '*':
            pass
        elif filespec == '+':
            if len(extras) == 0:
                state.do_test('Expected one or more trailing filenames, got none for "{}"'.format(cmd))
        else:
            assert False, 'Unrecognized string for pattern file spec "{}"'.format(filespec)
    elif isinstance(filespec, list):
        if filespec != extras:
            state.do_test('Filenames differ or not in order for command "{}"'.format(cmd))
    elif isinstance(filespec, set):
        if filespec != set(extras):
            state.do_test('Filenames differ for command "{}"'.format(cmd))
    else:
        assert False, 'Non-string pattern filespec not yet implemented "{}"'.format(filespec)


def _cmdline_check_constraints(state, cmd, constraints, opts):
    if constraints is None:
        return
    for (opt, arg) in opts:
        if opt in constraints:
            required = constraints[opt]
            if callable(required):
                if not required(arg):
                    state.do_test('Argument "{}" of flag "{}" for "{}" failed test'.format(arg, opt, cmd))
            elif type(required) == PAT_TYPE:
                if not required.search(arg):
                    state.do_test('Argument "{}" of flag "{}" for "{}" does not match pattern "{}"'.format(arg, opt, cmd, required.pattern))
            else:
                if arg != required:
                    state.do_test('Argument "{}" of flag "{}" for "{}" does not match required "{}"'.format(arg, opt, cmd, required))

import os
import re
from getopt import getopt, GetoptError
from protowhat.Test import TestFail
from shellwhat.sct_syntax import state_dec

__version__ = '0.1.2'

#-------------------------------------------------------------------------------

@state_dec
def test_compare_file_to_file(state, actualFilename, expectFilename, debug=None):
    '''Check if a file is line-by-line equal to another file (ignoring
    whitespace at the start and end of lines and blank lines at the
    ends of files).'''

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
    '''Return a list of whitespace-stripped lines from a file, or fail if
    the file cannot be found.  Remove blank lines from the end of the
    file.'''

    try:
        with open(filename, 'r') as stream:
           lines = [x.strip() for x in stream.readlines()]
    except Exception as err:
        state.do_test('Unable to open file {}'.format(filename))

    while not lines[-1]:
        del lines[-1]

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
        if pat.search(state.student_result):
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
def test_cmdline(state, pattern, redirect=None, msg=None, last_line=False, debug=None):
    line = _cmdline_select_line(state, last_line)
    actualCommands, actualRedirect = _cmdline_parse(state, line, msg, debug=debug)
    _cmdline_match_redirect(state, redirect, actualRedirect, msg, debug=debug)
    _cmdline_match_all_commands(state, pattern, actualCommands, msg, debug=debug)
    return state


def _cmdline_select_line(state, last_line):
    line = state.student_code.strip()
    if last_line:
        line = line.split('\n')[-1]
    return line


def _cmdline_parse(state, line, msg=None, debug=None):
    stripped, redirect = _cmdline_get_redirect(state, line, msg)
    commands = [_cmdline_parse_command(c.strip()) for c in stripped.strip().split('|')]
    return commands, redirect


def _cmdline_get_redirect(state, text, msg=None):

    if '>' not in text:
        return text, None
    if text.count('>') > 1:
        _cmdline_fail(state, 'Command line can contain at most one ">"', msg)

    pre, post = [x.strip() for x in text.split('>')]

    if not pre:
        _cmdline_fail(state, 'Line cannot start with redirection', msg)
    if not post:
        _cmdline_fail(state, 'Dangling ">" at end of line', msg)
    if '|' in post:
        _cmdline_fail(state, 'Cannot redirect to something containing a pipe "{}".format(post)', msg)
    if ' ' in post:
        _cmdline_fail(state, 'Cannot redirect to something containin spaces "{}"'.format(post), msg)

    return pre, post


def _cmdline_match_redirect(state, pattern, actual, msg=None, debug=None):
    if pattern is None:
        if actual:
            _cmdline_fail(state, 'Redirect found when none expected "{}"'.format(actual), msg, debug)
    elif isinstance(pattern, str):
        if pattern != actual:
            _cmdline_fail(state, 'Pattern "{}" does not match actual "{}"'.format(pattern, actual), msg, debug)
    elif type(pattern) == PAT_TYPE:
        if not pattern.search(actual):
            _cmdline_fail(state, 'Regular expression "{}" does not match actual "{}"'.format(pattern.pattern, actual), msg, debug)


def _cmdline_parse_command(text):
    return [_cmdline_strip_quotes(a) for a in PAT_ARGS.findall(text)]


def _cmdline_strip_quotes(val):
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1]
    return val


def _cmdline_match_all_commands(state, pattern, actual, msg=None, debug=None):
    if len(pattern) != len(actual):
        _cmdline_fail(state, 'Unexpected number of components in command line: expected "{}" found "{}"'.format(len(pattern), len(actual)), msg, debug)
    for (p, a) in zip(pattern, actual):
        _cmdline_match_command(state, p, a, msg, debug=debug)


def _cmdline_match_command(state, pattern, actual, msg=None, debug=None):

    # Command.
    assert len(pattern) > 0, 'Pattern must have at least a command name'
    assert len(actual) > 0, 'Command cannot be empty'

    # Disassemble pattern.
    pat_cmd, pat_optstring, pat_filespec, pat_constraints = _cmdline_disassemble_pattern(pattern)
    if pat_cmd != actual[0]:
        _cmdline_fail(state, 'Expected command "{}" got "{}"'.format(pat_cmd, actual[0]), msg, debug)

    # No parameters allowed.
    if pat_optstring is None:
        if len(actual) > 1:
            _cmdline_fail(state, 'Pattern does not allow parameters but actual command contains some "{}"'.format(actual), msg, debug)
        return state

    # Get actual flags, their arguments, and trailing filenames.
    try:
        actual_opts, actual_extras = getopt(actual[1:], pat_optstring)
    except GetoptError as e:
        raise TestFail(e)

    # Check trailing filenames both ways.
    _cmdline_check_filenames(state, pat_cmd, pat_filespec, actual_extras, msg, debug)

    # Check constraints.
    _cmdline_check_constraints(state, pat_cmd, pat_constraints, actual_opts, msg, debug)


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


def _cmdline_check_filenames(state, cmd, filespec, extras, msg=None, debug=None):

    # Nothing allowed.
    if filespec is None:
        if extras:
            _cmdline_fail(state, 'Unexpected trailing filenames "{}" for "{}"'.format(extras, cmd), msg, debug)

    # Filespec is a single string '*' (for zero or more) '+' (for one or more) or a filename.
    elif isinstance(filespec, str):
        if filespec == '*':
            pass
        elif filespec == '+':
            if len(extras) == 0:
                _cmdline_fail(state, 'Expected one or more trailing filenames, got none for "{}"'.format(cmd), msg, debug)
        else:
            if len(extras) != 1:
                _cmdline_fail(state, 'Expected one filename "{}", got "{}"'.format(filespec, extras), msg, debug)
            if extras[0] != filespec:
                _cmdline_fail(state, 'Expected filename "{}", got "{}"'.format(filespec, extras[0]), msg, debug)

    # Filespec is a single regular expression.
    elif type(filespec) == PAT_TYPE:
        if len(extras) != 1:
            _cmdline_fail(state, 'Expected one filename for "{}", got "{}"'.format(cmd, extras), msg, debug)
        if not re.search(filespec, extras[0]):
            _cmdline_fail(state, 'Filename "{}" does not match pattern "{}"'.format(extras[0], filespec.pattern), msg, debug)

    # Filespec is a list of strings or regular expressions that must match in order.
    elif isinstance(filespec, list):
        if len(filespec) != len(extras):
            _cmdline_fail(state, 'Wrong number of filename arguments for "{}"'.format(cmd), msg, debug)
        for (f, e) in zip(filespec, extras):
            if isinstance(f, str):
                if f != e:
                    _cmdline_fail(state, 'Filenames differ or not in order in list for command "{}"'.format(cmd), msg, debug)
            elif type(f) == PAT_TYPE:
                if not re.search(f, e):
                    _cmdline_fail(state, 'Filenames differ or not in order in list for command "{}" ("{}" vs pattern "{}")'.format(cmd, e, f), msg, debug)
            else:
                assert False, 'Filespec "{}" not yet supported in list'.format(filespec)

    # Filespec is a set of strings that must match all match (in any order).
    elif isinstance(filespec, set):
        if filespec != set(extras):
            _cmdline_fail(state, 'Filenames differ for command "{}": spec "{}" vs. actual "{}"'.format(cmd, filespec, extras), msg, debug)

    # Filespec isn't supported yet.
    else:
        assert False, 'Filespec "{}" not yet supported'.format(filespec)


def _cmdline_check_constraints(state, cmd, constraints, opts, msg=None, debug=None):
    if constraints is None:
        return
    for (opt, arg) in opts:
        if opt in constraints:
            required = constraints[opt]
            if callable(required):
                if not required(arg):
                    _cmdline_fail(state, 'Argument "{}" of flag "{}" for "{}" failed test'.format(arg, opt, cmd), msg, debug)
            elif type(required) == PAT_TYPE:
                if not required.search(arg):
                    _cmdline_fail(state, 'Argument "{}" of flag "{}" for "{}" does not match pattern "{}"'.format(arg, opt, cmd, required.pattern), msg, debug)
            elif required is None:
                if arg != '':
                    _cmdline_fail(state, 'Flag "{}" for "{}" should not have argument but has {}'.format(opt, cmd, arg), msg, debug)
            elif arg != required:
                _cmdline_fail(state, 'Argument "{}" of flag "{}" for "{}" does not match required "{}"'.format(arg, opt, cmd, required), msg, debug)
            del constraints[opt]
    if constraints:
        _cmdline_fail(state, 'Missing flag(s)'.format(cmd, ', '.join(constraints.keys())), msg, debug)


def _cmdline_fail(state, internal, external, debug):
    report = external if external else ''
    if debug:
        report = '{} ({})'.format(report, internal)
    state.do_test(report)

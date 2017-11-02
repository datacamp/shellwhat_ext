import pytest


class State(object):
    def __init__(self, student_result=''):
        self.student_result = student_result


def test_empty_matches_empty():
    t_cmdline(State(), [])


#-------------------------------------------------------------------------------


def t_cmdline(state, pattern, redirect=None, msg='Error'):
    '''FIXME'''

    patCommands, patRedirect = _cmdline_parse_pattern(pattern)
    actualCommands, actualRedirect = _cmdline_parse_actual(state.student_result)
    _cmdline_match_commands(patCommands, actualCommands)
    _cmdline_match_redirect(patRedirect, actualRedirect)
    return state


def _cmdline_parse_pattern(pattern):
    return [], None # FIXME


def _cmdline_parse_actual(text):
    return [], None # FIXME


def _cmdline_match_commands(patCommands, actualCommands):
    pass # FIXME


def _cmdline_match_redirect(patRedirect, actualRedirect):
    pass # FIXME

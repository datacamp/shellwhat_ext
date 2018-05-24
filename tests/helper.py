from protowhat.Reporter import Reporter
from shellwhat.State import State

def prepare_state(student_code=''):
    s = State(
        student_code = student_code,
        solution_code = "",
        reporter = Reporter(),
        pre_exercise_code = "",
        student_result = None,
        solution_result = None,
        student_conn = None,
        solution_conn = None)
    s.tc_msg = "Fail"
    return(s)

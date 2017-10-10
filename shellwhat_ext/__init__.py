def test_lines_compare(leftFilename, rightFilename):
    '''Return empty string if two text files are line-by-line equal
    (ignoring whitespace) and an error message if they are not.'''

    try:
        with open(leftFilename, 'r') as stream:
            leftList = stream.readlines()
        with open(rightFilename, 'r') as stream:
            rightList = stream.readlines()
    except Exception as err:
        return str(err)

    if len(leftList) != len(rightList):
        return 'Files have different lengths'

    leftList = [x.strip() for x in leftList]
    rightList = [x.strip() for x in rightList]

    diffs = []
    for (i, leftLine, rightLine) in zip(range(len(leftList)), leftList, rightList):
        if leftLine != rightLine:
            diffs.append(i+1)

    if diffs:
        return 'Line(s) differ: {}'.format(', '.join([str(x) for x in diffs]))

    return '' # all good

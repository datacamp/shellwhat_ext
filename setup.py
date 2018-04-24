import re
import ast
from setuptools import setup

_version_re = re.compile(r'__version__\s+=\s+(.*)')

with open('shellwhat_ext/__init__.py', 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

setup(name='shellwhat_ext',
      version=version,
      description='Extensions to shellwhat testing',
      url='https://github.com/datacamp/shellwhat_ext',
      author='Greg Wilson',
      author_email='greg@datacamp.com',
      license='MIT',
      packages=['shellwhat_ext'],
      install_requires=['protowhat>=0.5.0', 'shellwhat'],
      zip_safe=False)

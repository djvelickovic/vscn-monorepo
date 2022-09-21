from setuptools import find_packages, setup

setup(
    name='vscnc',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'requests',
        'click'
    ],
    scripts=[
        'bin/maven/maven_list.sh',
        'bin/maven/maven_pre_run.sh',
        'bin/pip/pip_list.sh',
        'bin/pip/pip_pre_run.sh',
    ],
    entry_points='''
        [console_scripts]
        vscnc=vscnc.app:cli
    ''',
    author='Djordje Velickovic'
)

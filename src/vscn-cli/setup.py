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
    entry_points='''
        [console_scripts]
        vscnc=vscn_cli.app:cli
    ''',
    author='Djordje Velickovic'
)

"""Test file with intentional security vulnerabilities for testing the scanner."""

import os
import pickle
import subprocess

import yaml

# CRITICAL: eval() - arbitrary code execution
def unsafe_eval(user_input):
    return eval(user_input)


# CRITICAL: exec() - arbitrary code execution
def unsafe_exec(code):
    exec(code)


# CRITICAL: subprocess with shell=True - command injection
def run_command_shell(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True)


# HIGH: os.system() - command injection
def run_system_command(cmd):
    os.system(cmd)


# HIGH: pickle.loads() - arbitrary code execution during deserialization
def load_pickle_data(data):
    return pickle.loads(data)


# HIGH: yaml.load() without SafeLoader - arbitrary code execution
def load_yaml_unsafe(yaml_string):
    return yaml.load(yaml_string)


# MEDIUM: subprocess without shell=True - still needs attention
def run_command_safe(cmd_list):
    return subprocess.run(cmd_list, capture_output=True)


# This is a test file - these vulnerabilities are intentional!
if __name__ == "__main__":
    print("This file contains intentional vulnerabilities for testing.")

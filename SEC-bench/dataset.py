from datasets import load_dataset

ds = load_dataset("SEC-bench/SEC-bench")
before = ds['before']
after  = ds['after']
eval_  = ds['eval']

print(before)
print(after)
print(eval_)
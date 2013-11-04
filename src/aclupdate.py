# -.- coding:utf-8 -.-
import os
import subprocess
import sys

def main():
	"""
	Read a list of ACLs from either a file or standard input
	and modify the file system such that the ACLs are enforced.
	"""
	acls = parse()
	queue = acls.keys()
	pointer = 0
	while len(queue) > pointer:
		path = queue[pointer]
		acl = get_nearest_acl(acls, path)
		
		pointer += 1
		children = []
		recursive = reduce(
				lambda recurs, str:
					recurs and str != 'nonrecursive',
				acl,
				True
			)
		if not recursive:
			execute_commands(path, acl, False)
		else:
			has_child = reduce(
					lambda has_child, pathname:
						pathname.startswith(path+os.sep) and path != pathname or has_child,
					queue,
					False
				)
			if has_child:
				recursive = False
				acl.append('nonrecursive')
				children = os.listdir(path)
				children = map(lambda x: os.path.join(path,x), children)
				queue.extend(filter(lambda x: x not in queue, children))
			execute_commands(path, acl, recursive)

def execute_commands(path, acl, recursive):
	"""
	Construct commands to apply the acl on path, and run them.
	"""
	if 'nonrecursive' in acl:
		acl.remove('nonrecursive')
	add_acl = ','.join(acl)
	subprocess.call('setfacl '+path+' -'+ ('R' if recursive else '') + 'm '+add_acl, shell=True)

def get_nearest_acl(acls, path):
	"""
	Get the ACL that matches the path best.
	It does so by trying to get the path as-is from the acl list
	and if that fails it will get the parent path.
	"""
	if path in acls:
		return acls[path]
	if not path or path == '/':
		sys.exit('root path not defined (this may be a bug)')
	return get_nearest_acl(acls, os.path.abspath(os.path.join(path, os.pardir)))

def parse():
	"""
	Read ACLs from either a file or standard input and return them in a dictionary with path as key and acl array as value.
	"""
	acls = {}
	if len(sys.argv) > 2:
		sys.exit('Usage: '+sys.argv[0]+' [filename]')
	if len(sys.argv) > 1:
		ruleList = open(sys.argv[1])
	else:
		ruleList = sys.stdin
	for rule in ruleList:
		path, perms = rule.strip().split('\t')
		acls[path.rstrip(os.sep)] = perms.split(',')
	return acls

main()

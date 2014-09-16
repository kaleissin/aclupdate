# -.- coding:utf-8 -.-
import os
import re
import subprocess
import sys

def add_default(x): return 'd:'+x

class AclSet:
	def __init__(self, rule_set, path):
		self.path = path
		self.add_acl = set()
		self.rec_add_acl = set()
		self.del_acl = set()
		self.rec_del_acl = set()
		self.reset = False

		self.parse_rule_set(rule_set, path)

	def parse_rule_set(self, rule_set, path):
		is_parent = False
		while path.rstrip(os.sep) and not self.reset:
			if path in rule_set:
				self.parse_rules(rule_set[path], is_parent)
			is_parent = True
			path = os.path.abspath(os.path.join(path, os.pardir))

	def parse_rules(self, rules, is_parent):
		for rule in rules:
			category, body = rule.split(':', 1)
			if category == 'r' or category == 'reset':
				self.reset = True
			elif category == 'l' or category == 'local':
				if not is_parent:
					self.parse_rule(body, False)
			elif (category == 'u' or category == 'user'
				or category == 'g' or category == 'group'
				or category == 'o' or category == 'other'
				or category == 'm' or category == 'mask'):
				self.parse_rule(rule, True)
			else:
				raise Exception('Unknown rule '+rule)

	def parse_rule(self, rule, recursive):
		if re.match('^(u(ser)?|g(roup)?|o(ther)?|m(ask)?):[a-z0-9-\\\\]*:([rwxX]+|[0-7]{1,3})$', rule):
			if recursive:
				self.rec_add_acl.add(rule)
			else:
				self.add_acl.add(rule)
		elif re.match('^(u(ser)?|g(roup)?|o(ther)?|m(ask)?):[a-z0-9-\\\\]+:?$', rule):
			if recursive:
				self.rec_del_acl.add(rule)
			else:
				self.del_acl.add(rule)
		else:
			raise Exception('Unknown rule '+rule)

	def cmd_recursive(self):
		if self.rec_add_acl or self.rec_del_acl:
			self.cmd(
					'echo setfacl -R', 
					self.rec_add_acl | set(map(add_default, self.rec_add_acl)),
					self.rec_del_acl | set(map(add_default, self.rec_del_acl))
				)
		self.cmd('echo setfacl', self.add_acl, self.del_acl)

	def cmd_local(self):
		if self.add_acl or self.del_acl:
			self.cmd(
					'echo setfacl',
					self.add_acl | self.rec_add_acl | set(map(add_default, self.rec_add_acl)),
					self.del_acl | self.rec_del_acl | set(map(add_default, self.rec_del_acl))
				)

	def cmd(self, cmd_basis, add_acl, del_acl):
		if add_acl or del_acl:
			if self.reset:
				cmd_basis += ' -b'
			if add_acl:
				cmd_basis += ' -m ' + ','.join(add_acl)
			if del_acl:
				cmd_basis += ' -x ' + ','.join(del_acl)
			cmd_basis += ' ' + self.path
			subprocess.call(cmd_basis, shell=True)

def main(acl_rules):
	"""
	Read a list of ACLs from either a file or standard input
	and modify the file system such that the ACLs are enforced.
	"""
	queue = acl_rules.keys()
	pointer = 0
	while len(queue) > pointer:
		path = queue[pointer]
		pointer += 1
		acls = AclSet(acl_rules, path)
		
		# TODO: Check if there is a conflict between a l: rule and another rule.
		# If so, assume there is a child path and only apply the l: here 
		has_child_path = reduce(
				lambda has_child_path, path_:
					has_child_path or path_.startswith(path+os.sep),
				queue,
				False
			)
		if has_child_path:
			child_paths = os.listdir(path)
			child_paths = map(lambda x: os.path.join(path,x), child_paths)
			queue.extend(filter(lambda path_: path_ not in queue, child_paths))
			acls.cmd_local()
		else:
			acls.cmd_recursive()

def parse():
	"""
	Read ACLs from either a file or standard input and return them in a dictionary with path as key and acl array as value.
	"""
	rules = {}
	if len(sys.argv) > 2:
		sys.exit('Usage: '+sys.argv[0]+' [filename]')
	if len(sys.argv) > 1:
		ruleList = open(sys.argv[1])
	else:
		ruleList = sys.stdin
	for rule in ruleList:
		path, perms = rule.strip().split('\t')
		path = path.rstrip(os.sep)
		if path in rules:
			rules[path].extend(perms.split(','))
		else:
			rules[path] = perms.split(',')
	return rules

main(parse())

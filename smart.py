import r2pipe

r = r2pipe.open('./SMarT-solver')
r.cmd('aaa')

start = 0x00000926
step = 0x16

def off_from_esil(esil):
	parts = esil.split(',')
	return int(parts[0], 0)

less_thans = [[i, 0] for i in range(73)]

while True:
	r.cmd('s 0x%x' % (start))
	d = r.cmdj('pDj %d' % (step))

	if d[2]['disasm'] != 'cmp dl, al':
		break

	off0 = 0x120 - off_from_esil(d[0]['esil'])
	off1 = 0x120 - off_from_esil(d[1]['esil'])

	if d[3]['opcode'].startswith('jbe'):
		less_thans[off0][1] += 1

	start += step

less_thans.sort(key=lambda lt : lt[1])

flag = ['_'] * 73
alpha = "abcdefghijklmnopqrstuvwxyz{}"

index = 0
prev = 0

for lt in less_thans:
	if lt[1] != prev:
		prev = lt[1]
		index += 1
	flag[lt[0]] = alpha[index]

print(''.join(flag))

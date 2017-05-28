import logging
from winrm.protocol import Protocol

logging.getLogger("requests_kerberos").setLevel(logging.DEBUG)

p = Protocol(
    endpoint='https://DC01.jordan.local:5986/wsman',
    transport='kerberos',
    #transport='ntlm',
    #username=r'JORDAN\Administrator',
    #password='Password02',
    server_cert_validation='ignore')
shell_id = p.open_shell()
command_id = p.run_command(shell_id, 'ipconfig', ['/all'])
std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
p.cleanup_command(shell_id, command_id)
p.close_shell(shell_id)

print("STDOUT: %s" % std_out)
print("STDERR: %s" % std_err)
print("RETURN: %d" % status_code)

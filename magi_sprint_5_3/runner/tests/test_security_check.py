import socket, threading
from magi_runner.executors.security_check import SecurityCheckExecutor

def test_tcp_open_check(tmp_path):
    server=socket.socket(); server.bind(('127.0.0.1',0)); server.listen(1); port=server.getsockname()[1]
    t=threading.Thread(target=lambda: server.accept()[0].close(),daemon=True); t.start()
    result=SecurityCheckExecutor().run({'target':'127.0.0.1','payload':{'target':'127.0.0.1','task_key':'TEST','detection':{'type':'tcp_port','port':port,'finding_when':'open'}}},str(tmp_path),3)
    server.close()
    assert result.status=='success'
    assert result.metadata['finding']['detected'] is True
    assert result.metadata['evidence']['state']=='open'

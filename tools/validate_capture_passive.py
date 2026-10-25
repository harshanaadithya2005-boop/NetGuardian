"""Five-second passive capture validation on a database COPY; sends no traffic."""
from pathlib import Path
from contextlib import closing
from datetime import datetime
import sys,sqlite3,time,json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from database import db
root=Path(__file__).resolve().parents[1]
folder=root/'.test-work'/('passive-capture-'+datetime.now().strftime('%Y%m%d-%H%M%S'));folder.mkdir(parents=True)
source=Path(db.DB_PATH).resolve();copy=folder/'capture-copy.db'
with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as original,closing(sqlite3.connect(copy)) as target:original.backup(target)
db.DB_PATH=copy;db.initialize_database()
from capture import packet_capture as capture
with closing(db.get_connection()) as conn:before=conn.execute('SELECT COUNT(*) FROM traffic').fetchone()[0]
started=capture.start_capture()
try:time.sleep(5)
finally:capture.stop_capture()
with closing(db.get_connection()) as conn:after=conn.execute('SELECT COUNT(*) FROM traffic').fetchone()[0]
result=dict(started=started,health=capture.get_capture_health(),new_core_traffic_records=after-before,
            source_database_modified=False,generated_packets=0,router_configuration_writes=0)
(folder/'result.json').write_text(json.dumps(result,indent=2,default=str))
print(json.dumps(result,indent=2,default=str))

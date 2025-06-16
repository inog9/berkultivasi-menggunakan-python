#pip install watchdog

from watchdog.observers import Observer
from watchdog.events import FileSystemHandler
import time

class MonitorHandler(FileSystemHandler):
    def on_modified(self,event):
        print(f"[modified]{event.src_path}" )

    def on_created(self,event):
        print(f"[Created]{event.src_path}" )
    
    def on_deleted(self,event):
        print(f"[Deleted]{event.src_path}" )

def watch_directory(path):
    observer = Observer
    handler = MonitorHandler()
    observer.schedule(handler, path=path, recursive=True)
    observer.start()
    print(f"[INFO] Watching {path}... press CTRL+c to stop.")

    try: 
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

#pemakaian
watch_directory("/tmp")
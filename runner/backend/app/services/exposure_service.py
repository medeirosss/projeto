from app.repositories import exposure_repository as repo

def evaluate_target(target_id:int): return repo.evaluate_target(target_id)
def rebuild_all(): return repo.rebuild_all()

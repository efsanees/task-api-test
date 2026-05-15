"""Task API — basit görev yönetimi."""

def get_tasks():
    return []

def add_task(title: str, description: str = ""):
    return {"title": title, "description": description, "done": False}

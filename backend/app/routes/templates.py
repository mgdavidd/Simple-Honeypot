from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, Header
from sqlalchemy.orm import Session
from pathlib import Path

from ..database import get_db
from ..models import AdminUser
from ..auth import get_current_user_from_cookie

router = APIRouter()

TEMPLATES_DIR = Path("/app/honeypot_templates")


@router.get("/api/templates")
def list_templates(
    current_user: AdminUser = Depends(get_current_user_from_cookie),
):
    """Listar plantillas disponibles."""
    templates = []
    
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    
    for file in TEMPLATES_DIR.glob("*.sql"):
        size_kb = file.stat().st_size / 1024
        templates.append({
            "name": file.stem,
            "filename": file.name,
            "size": file.stat().st_size,
            "size_kb": f"{size_kb:.1f}",
            "type": "default" if file.stem in ["empty", "wordpress", "ecommerce"] else "custom"
        })
    
    return {"templates": sorted(templates, key=lambda x: x['name']), "count": len(templates)}


@router.post("/api/templates/upload")
async def upload_template(
    file: UploadFile,
    current_user: AdminUser = Depends(get_current_user_from_cookie)
):
    """Subir plantilla SQL personalizada."""
    
    if not file.filename.endswith(".sql"):
        raise HTTPException(status_code=400, detail="Only .sql files allowed")
    
    content = await file.read()
    
    # Validar que sea SQL
    if not (b"SELECT" in content.upper() or b"CREATE" in content.upper()):
        raise HTTPException(status_code=400, detail="File doesn't look like valid SQL")
    
    # Limpiar nombre
    template_name = file.filename.replace(".sql", "").replace(" ", "_").lower()
    
    # No permitir nombres de templates por defecto
    if template_name in ["empty", "wordpress", "ecommerce"]:
        raise HTTPException(status_code=409, detail="Cannot use reserved template names")
    
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    filepath = TEMPLATES_DIR / f"{template_name}.sql"
    
    # No permitir sobrescribir si ya existe
    if filepath.exists():
        raise HTTPException(status_code=409, detail=f"Template '{template_name}' already exists")
    
    try:
        with open(filepath, 'wb') as f:
            f.write(content)
        
        print(f"[api] Template '{template_name}' uploaded by {current_user.username} ({len(content)} bytes)")
        
        return {
            "message": "Template uploaded successfully",
            "name": template_name,
            "size": len(content),
            "type": "custom"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading template: {str(e)}")


@router.delete("/api/templates/{template_name}")
def delete_template(
    template_name: str,
    current_user: AdminUser = Depends(get_current_user_from_cookie)
):
    """Eliminar plantilla personalizada (no defaults)."""
    
    if template_name in ["empty", "wordpress", "ecommerce"]:
        raise HTTPException(status_code=403, detail="Cannot delete default templates")
    
    filepath = TEMPLATES_DIR / f"{template_name}.sql"
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Template not found")
    
    try:
        filepath.unlink()
        print(f"[api] Template '{template_name}' deleted by {current_user.username}")
        
        return {"message": "Template deleted successfully", "name": template_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting template: {str(e)}")
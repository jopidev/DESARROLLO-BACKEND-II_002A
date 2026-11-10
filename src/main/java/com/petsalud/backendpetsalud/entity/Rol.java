package com.petsalud.backendpetsalud.entity;

/**
 * Roles definidos por el cliente (Clinica PetSalud).
 * CLIENTE  : duenos de mascotas, solo acceden a sus propios datos.
 * EMPLEADO : veterinarios y personal de sucursal (atencion, inventario, expedientes).
 * GERENTE  : administracion, reportes, gestion de usuarios y auditoria.
 */
public enum Rol {
    CLIENTE,
    EMPLEADO,
    GERENTE
}

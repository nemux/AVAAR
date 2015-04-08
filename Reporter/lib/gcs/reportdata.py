#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
package.module
~~~~~~~~~~~~~

A description which can be long and explain the complete
functionality of this module even with indented code examples.
Class/Function however should not be documented here.

:copyright: 2014 by NeMuX, see AUTHORS for more details
:license: Apache 2.0, see LICENSE for more details
"""

__author__ = "NeMuX"
__copyright__ = "Copyright 2014"
__credits__ = ["NeMuX"]
__license__ = "Apache 2.0"
__version__ = "0.1"
__maintainer__ = "NeMuX"
__email__ = "jaraujo@globalcybersec.com"
__status__ = "Development"


import os
#import sys
import csv
import sqlite3

from gcs.utils import *

def crear_bd_temporal(archivo):
    conn = sqlite3.connect('./tmp/temp.db')
    conn.text_factory =str
    c = conn.cursor()

    c.execute("DROP TABLE IF EXISTS temp_data")

    c.execute('''CREATE TABLE temp_data (id INTEGER PRIMARY KEY AUTOINCREMENT, Nombre_de_Vulnerabilidad TEXT,
                NessusID TEXT, CVE TEXT, CVSS TEXT, Prioridad TEXT, Severidad NUMERIC, IP TEXT, HOSTNAME TEXT, Protocolo TEXT, PUERTO TEXT, Plataforma TEXT, Descripcion TEXT,
                Solucion TEXT, Familia_de_Plugins TEXT, Nombre_de_Plugin TEXT, Tipo_de_Servicio TEXT, Categoria TEXT, Referencias)''')

    csv_file = open(archivo)
    reader = csv.reader(csv_file)
    rownum = 0
    colnum = 0

    for r in reader:
        #ignoro el encabezado
        if rownum == 0:
            colnum = len(r)
            rownum = rownum +1
        else:
            #Llenamos la tupla
            reg = tuple(r)
            c.execute('''INSERT INTO temp_data (Nombre_de_Vulnerabilidad, NessusID, CVE, CVSS, Prioridad, Severidad, IP, HOSTNAME, Protocolo,
                         PUERTO, Plataforma, Descripcion, Solucion, Familia_de_Plugins, Nombre_de_Plugin, Tipo_de_Servicio, Categoria, Referencias)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', reg[0:-1])
        rownum = rownum + 1
    conn.commit()
    c.close()
    conn.close()

def eliminar_bd_temporal(db_name='./tmp/temp.db'):
    try:
        os.remove(db_name)
    except (OSError, IOError) as e:
        print("ERROR: " + str(e.errno))

def __get_db_data__(query, *params):
    conn = sqlite3.connect('./tmp/temp.db')
    conn.text_factory =str
    c = conn.cursor()
    args =()

    if (len(params)) > 0:
        l = []
        for p in params:
            l.append(p)
        args = tuple(l[0])
        c.execute(query,args)
    else:
        c.execute(query)

    data = c.fetchall()
    c.close()
    conn.close()

    return data

def get_all_vuln_list():
   return __get_db_data__(''' SELECT DISTINCT NessusID FROM temp_data ORDER BY NessusID ASC''')

def get_vuln_list_by_priority(vuln_info,priority):
    '''
        Obtenemos una lista de las vulnerabilidades que se encuentran en el reporte, deacuerdo a la Prioridad
        solicitada.
    '''
    Priority = enum('NONE','LOW','MEDIUM','HIGH')
    vuln_list = []
    '''
    for v in vuln_info:
        if priority > Priority.MEDIUM and v[5] >= Priority.HIGH:
            vuln_list.append(int(v[0]))
        else:
            if v[5] == priority:
                vuln_list.append(int(v[0]))
    '''
    for v in vuln_info:
        if priority > Priority.MEDIUM:
            if v[5] >= Priority.HIGH:
                vuln_list.append(int(v[0]))
        else:
            if v[5] == priority:
                vuln_list.append(int(v[0]))
    vuln_list_order = list(set(vuln_list))
    vuln_list_order.sort()
    return vuln_list_order

def get_all_ip_list():
   return __get_db_data__(''' SELECT DISTINCT IP FROM temp_data ORDER BY IP ASC''')

def get_info_vuln_by_priority(segmento,prioridad):
    '''
        Obtenemos una lista de las vulnerabilidades y su informacion que se encuentran en el reporte, deacuerdo a la Prioridad
        solicitada.
    '''
    vuln_data = []
    query = ""

    if prioridad > 2:
        query = '''  SELECT  NessusID, Nombre_de_Vulnerabilidad, IP, Protocolo,
                                Puerto, Severidad, Prioridad, Descripcion, Solucion, Categoria, CVE, CVSS, Referencias
                                FROM temp_data
                                WHERE Severidad >= ?
                                GROUP BY NessusID, IP
                                ORDER BY Severidad DESC, NessusID ASC '''
    else:
        query = '''  SELECT NessusID, Nombre_de_Vulnerabilidad, IP, Protocolo,
                                Puerto, Severidad, Prioridad, Descripcion, Solucion, Categoria, CVE, CVSS, Referencias
                                FROM temp_data
                                WHERE Severidad = ?
                                GROUP BY NessusID, IP
                                ORDER BY Severidad DESC, NessusID ASC '''
    tmp_data = __get_db_data__(query, (prioridad,))
    for t in tmp_data:
        if t[2] in segmento:
            vuln_data.append(t)
    return vuln_data

def get_category_list_by_priority(segmento,prioridad):

    query = ""
    cat_list = []

    if prioridad > 2:
        query = '''SELECT IP,Categoria
                   FROM temp_data
                   WHERE severidad >= ?'''
    else:
        query = '''SELECT IP,Categoria
                    FROM temp_data
                    WHERE severidad = ?'''
    tmp_data = __get_db_data__(query,(prioridad,))


    for t in tmp_data:
        if t[0] in segmento:
            cat_list.append(t[1])

    cat_list = list(set(cat_list))

    return cat_list

def get_vuln_category_total(vuln_list, category_list):

    cat_list = {}

    #inicializamos los totales en 0
    for c in category_list:
        cat_list[c] = 0

    #Verificamos la categoria de cada vulnerabilidad y la sumamos
    for v in vuln_list:
        data = __get_db_data__('''SELECT DISTINCT(Categoria) FROM temp_data WHERE NessusID=?''',(v,))
        for c in category_list:
            #print("UNICODE->" + unicode_string(data[0][0]))
            #print("C[0]->" + c + "\n")
            if unicode_string(data[0][0]) == c:
                cat_list[c] = cat_list[c] + 1
    return cat_list


def get_ip_hostname_list(segmento):
    '''
        Obtenemos la lista de IP de Archivo.
        La consulta 1 es para obtener todas las IP, la consulta 2 es para opbtener solo las IP con vulnerabilidades altas.
    '''

    temp_data = []
    ip_list =[]

    temp_data = __get_db_data__('''SELECT ip, hostname FROM temp_data GROUP BY IP''')
    #temp_data = __get_db_data__('''SELECT ip, hostname FROM temp_data WHERE severidad >= 3 GROUP BY IP''')

    for t in temp_data:
        if t[0] in segmento:
            ip_list.append(t)

    return  ip_list

def get_ip_high_vuln(segmento,prioridad):

    query = ""
    tmp_data = []
    vuln_data = []

    if prioridad > 2:
        query = "SELECT DISTINCT(ip) FROM temp_data WHERE severidad>=?"
    else:
        query = "SELECT DISTINCT(ip) FROM temp_data WHERE severidad=?"

    tmp_data = __get_db_data__(query, (prioridad,))

    for t in tmp_data:
        if t[0] in segmento:
            vuln_data.append(t)
    return vuln_data

def get_ip_list_by_priority(segmento,prioridad):

    query = ""
    tmp_data = []
    vuln_data = []

    if prioridad > 2:
        query = "SELECT DISTINCT(ip) FROM temp_data WHERE severidad>=?"
    else:
        query = "SELECT DISTINCT(ip) FROM temp_data WHERE severidad=?"

    tmp_data = __get_db_data__(query, (prioridad,))

    for t in tmp_data:
        if t[0] in segmento:
            vuln_data.append(t)
    return vuln_data

def clean_no_high_vulns(ip_list,vuln_info):

    tmp_data = []
    high_ip_list = []

    for i in ip_list:
        high_ip_list.append(i[0])

    for vi in vuln_info:
        if vi[2] in high_ip_list:
            tmp_data.append(vi)

    return tmp_data

def get_lack_updates(segmento,prioridad):
    query = ""
    tmp_data = []
    vuln_data = []

    if prioridad > 2:
        query = "SELECT DISTINCT nombre_de_vulnerabilidad, ip FROM temp_data WHERE severidad >= ?"
    else:
        query = "SELECT DISTINCT nombre_de_vulnerabilidad, ip FROM temp_data WHERE severidad = ?"

    tmp_data = __get_db_data__(query, (prioridad,))

    for t in tmp_data:
        if t[1] in segmento:
            vuln_data.append(t)

    tmp_data = []
    for v in vuln_data:
        tmp_data.append(v[0])

    vuln_data = set(tmp_data)
    return vuln_data


def getNetwork(ip_info):
    class_list=[]
    for ip in ip_info:
        class_a=ip.split(".")[0]
        class_b=ip.split(".")[1]
        class_c=ip.split(".")[2]
        segment=class_a+"."+class_b+"."+class_c+".0/24"
        if  segment not in class_list:
            class_list.append(segment)
    return class_list






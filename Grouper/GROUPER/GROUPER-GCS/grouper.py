#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
package.module
~~~~~~~~~~~~~

A description which can be long and explain the complete
functionality of this module even with indented code examples.
Class/Function however should not be documented here.

:copyright: 2014 by NeMuX, see AUTHORS for more details
:license: BDS license_name, see LICENSE for more details
"""

__author__ = "NeMuX"
__copyright__ = "Copyright 2014"
__credits__ = ["NeMuX"]
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "NeMuX"
__email__ = "jaraujo@globalcybersec.com"
__status__ = "Development"

import os
import sys
import copy
import re
import lxml
import csv
import sqlite3
from lxml import etree

def read_dir_files(dir = "./in", extension = ".nessus"):
    '''
    Retorna los nombres de los archivos que se encuentran en el directorio indicado,
    por defecto ./IN que correspondan a los archivos que se buscan por una extension
    determinada, por defecto .nessus

    @param dir: Directorio a enlistar (por defecto ./IN)
    @param extension: Extension del archivo a buscar (por defecto .nessus)

    @return files: Lista de los nombres de archivos encontrados
    '''
    files = []
    for fi in os.listdir(dir):
        if fi.endswith(extension):
            files.append((os.path.join(dir,fi)))
    #for f in files:
    #    print("Archivo->" + f)
    return files


def get_xml_info(xmlfilename):

    '''
   Retorna una lista con los diccionarios de las vulnerabilidades por equipo encontradas
   @param xmlfilename: nombre del archivo .nessus que se analizará

   @return vuln: lista los duccionarios de vulnerablidades encontradas.
    '''
    #print("Analizando el archivo->" + xmlfilename)
    #print("get_xml_info(xmlfilename)")
    vuln = []
    '''
    context = etree.iterparse(xmlfilename,events=('start','end',),tag='ReportHost')
    for event,element in context:
        print("Etiqueta (ELEMENT)->" + element.tag + " ::::: Atributos->" + str(element.attrib))
        print("EVENTO (EVENT)->" + event + " ::::: Atributos->" + str(element.attrib))
        #ip = element.attrib["name"]
        for l in list(element):
            hostInfo = {}
            #hostInfo["ip"] = ip
            print("Etiqueta(L)->" + l.tag + " ::::: Atributos->" + str(l.attrib))
            if l.tag == "ReportItem":
                hostInfo.update(dict(l.attrib))
                print(str(hostInfo))
                vuln.append(hostInfo)
            l.clear()
        element.clear()
    '''
    ''' FUNCION CHIDA
    context = etree.iterparse(xmlfilename,events=('start','end',),tag='ReportHost')
    context = iter(context)
    event, root = context.__next__()
    for event, elem in context:
        if event == "end" and elem.tag == "ReportHost":
            #print(elem.attrib)
            for l in elem:
                hostInfo = {}
                hostInfo["ip"] = elem.attrib["name"]
                if l.tag =="ReportItem":
                    hostInfo.update(dict(l.attrib))
                    #print(str(hostInfo))
                    vuln.append(hostInfo)
                l.clear()
            root.clear()
    '''

    context = etree.iterparse(xmlfilename,events=('start','end',),tag=['ReportHost'])
    context = iter(context)
    event, root = context.__next__()
    for event, elem in context:
        if event == "end" and elem.tag == "ReportHost":
            #print(elem.attrib)
            hostname = ""
            for l in elem:
                hostInfo = {}
                hostInfo["ip"] = elem.attrib["name"]

                #print(l.tag)
                if l.tag == "HostProperties":
                    for n in l:
                        if n.tag == "tag" and n.attrib['name']== 'host-fqdn':
                            #print(str(n.text))
                            hostname = n.text

                hostInfo.update(dict(hostname=hostname))

                if l.tag =="ReportItem":
                    hostInfo.update(dict(l.attrib))
                    #print(str(hostInfo))
                    vuln.append(hostInfo)
                    cvss = {}
                    for n in l:
                        if n.tag == "description":
                            hostInfo.update(dict(description=n.text))
                        if n.tag == "plugin_name":
                            hostInfo.update(dict(plugin_name=n.text))
                        if n.tag == "solution":
                            hostInfo.update(dict(solution=n.text))
                        if n.tag == "risk_factor":
                            hostInfo.update(dict(risk_factor=n.text))
                        if n.tag == "cve":
                            hostInfo.update(dict(cve=n.text))
                        if n.tag == "cvss_base_score":
                            cvss.update(dict(cvss_base_score=n.text))
                        if n.tag == "cvss_vector":
                            cvss.update(dict(cvss_vector=n.text))
                        if n.tag == "see_also":
                            hostInfo.update(dict(see_also=n.text))
                        if "cvss_vector" in cvss:
                            if "cvss_vector" in cvss:
                                hostInfo.update(dict(cvss=cvss["cvss_base_score"] +" " +cvss["cvss_vector"]))
                    #print(str(hostInfo))
                l.clear()
            root.clear()
    return vuln


def get_spanish_info_by_nessusid(nessusid,dbfile = "./info/vulnerabilidades.db"):
    '''
    Obtiene la informacion en español en la base de datos de vulnerabilidades a partir del
    Nessus ID solicitado

    @param nessusid: Nessus ID a buscar en la BD de vulnerabilidades

    @return spanish_info: Devuelve una lista de diccionarios con la informacion del plugin encontrada o un diccionario vacio si no se encontro nada.

    '''

    #spanish_info = {"nombre_vulnerabilidad": "UPS!","nessus_id":nessusid,"cve":"","cvss":"","prioridad":"","descripcion":"","solucion":""}
    spanish_info = {"Nombre_de_Vulnerabilidad": "_UPS_","Prioridad":"","Plataforma":"","CVE":"","CVSS":"","Descripcion":"","Solucion":"","Referencias":""}
    #spanish_info = {"Nombre_de_Vulnerabilidad": "_UPS_","Prioridad":"","Plataforma":"","CVE":"","CVSS":""}
    traducction = []

    #print("get_spanish_plugin_info(nessusid)")
    db = sqlite3.connect(dbfile)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    query = """SELECT nombre_vulnerabilidad as Nombre_de_Vulnerabilidad,
               prioridad AS Prioridad,
               plataforma AS Plataforma,
               cve AS CVE,
               cvss AS CVSS,
               descripcion AS Descripcion,
               solucion AS Solucion,
               categoria AS Categoria,
               referencias AS Referencias
               FROM vulnerabilidades WHERE nessus_id=? """
    cursor.execute(query,(nessusid,))
    #row_data = cursor.fetchone()
    row_data = cursor.fetchall()
    db.close()

    if len(row_data) > 0:
        for r in row_data:
            row_header = r.keys()
            for count in range(len(row_header)):
                spanish_info[row_header[count]] = r[row_header[count]]
                #spanish_info["NessusID"] = nessusid
                #print("TRADUCCION"  + str(spanish_info))
            traducction.append(dict(spanish_info))
            #print(str(traducction))
    else:
        traducction.append(dict(spanish_info))
        #print(str(traducction))
    row_data.clear()
    #print(traducction)
    return traducction


def open_csv_file(filename, extension,mode,dir="./tmp"):
    '''
    Abre un archivo csv

    @param dir: Directorio a enlistar (por defecto ./IN)
    @param extension: Extension del archivo a buscar (por defecto .nessus)

    @return files: Lista de los nombres de archivos encontrados
    '''
    fn = os.path.basename(filename)
    nm = os.path.splitext(fn)[0]
    nm = nm + extension
    file = os.path.join(dir,nm)
    return open(file,mode)


def close_csv_file(filename):
    filename.close()


def write_csv_parsed_file(file,data,files_num):
    fieldnames = ('Nombre_de_Vulnerabilidad', 'NessusID', 'CVE', 'CVSS','Prioridad', 'Severidad','IP','Hostname','Protocolo',
                  'Puerto','Plataforma','Descripcion','Solucion','Familia_de_Plugins','Nombre_de_Plugin','Tipo_de_Servicio','Categoria',"Referencias",
                  'Traduccion')

    writer = csv.DictWriter(file, fieldnames=fieldnames)
    headers = dict( (n,n) for n in fieldnames )
    #print(headers.__str__())
    if (files_num == 1):
        writer.writerow(headers)
    for row in data:
        if ( "Severidad" in row):
            if (row["Severidad"] != 0):
                writer.writerow(row)
        #else:
            #print(row)
    #writer.writerow(data )
    data.clear()
    return file


def merge_info(vuln_info,spanish_info):
    #print("merge_info(vuln_info,spanish_info)")
    #Devolovemos un diccionario
    output_string = {}
    tmp_spanish ={}
    descripcion = []
    solucion = []
    plataforma = []
    prioridad = []
    nombre_vulnerabilidad = []
    cve =[]
    cvss =[]
    referencias = []
    spanish_key= {"pluginID":"NessusID","ip":"IP","port":"Puerto","protocol":"Protocolo",
                  "svc_name":"Tipo_de_Servicio","risk_factor":"Prioridad","pluginFamily":"Familia_de_Plugins","pluginName":"Nombre_de_Plugin",
                  "plugin_name":"Nombre_de_Vulnerabilidad","solution":"Solucion","description":"Descripcion", "severity":"Severidad",
                  "hostname":"Hostname","cve":"CVE","see_also":"Referencias","cvss":"CVSS"}
    #print(str(vuln_info))
    #print(str(spanish_info))
    for inf in vuln_info.keys():
        tmp_spanish[spanish_key[inf]] = vuln_info[inf]
    output_string.update(tmp_spanish)
    #print(str(output_string))
    #print(tmp_spanish)
    #print(str(spanish_info))
    if spanish_info[0]["Nombre_de_Vulnerabilidad"] != "_UPS_":
        cont = 0
        for si in spanish_info:
            #output_string.update(spanish_info)
            descripcion.append(si["Descripcion"])
            descripcion.append("\n")
            solucion.append(si["Solucion"])
            solucion.append("\n")
            plataforma.append(si["Plataforma"])
            plataforma.append("\n")
            if cont == 0:
                nombre_vulnerabilidad.append(si["Nombre_de_Vulnerabilidad"])
                prioridad.append(si["Prioridad"])
                cvss.append(si["CVSS"])
            else:
                if (si["Nombre_de_Vulnerabilidad"] not in nombre_vulnerabilidad):
                    nombre_vulnerabilidad.append("\n")
                    nombre_vulnerabilidad.append(si["Nombre_de_Vulnerabilidad"])
                if (si["Prioridad"] not in  prioridad):
                    prioridad.append("\n")
                    prioridad.append(si["Prioridad"])
                if (si["CVSS"] not in cvss):
                    cvss.append("\n")
                    cvss.append(si["CVSS"])
            cve.append(si["CVE"])
            cve.append("\n")
            referencias.append(si["Referencias"])
            referencias.append("\n")
            cont = cont + 1
        output_string["Descripcion"] = ''.join(descripcion)[:-1]
        output_string["Solucion"] = ''.join(solucion)[:-1]
        output_string["Plataforma"] = ''.join(plataforma)[:-1]
        output_string["Nombre_de_Vulnerabilidad"] = ''.join(nombre_vulnerabilidad)
        output_string["Traduccion"] = "OK"
        output_string["Prioridad"] = ''.join(prioridad)
        output_string["Categoria"] = spanish_info[0]["Categoria"]
        output_string["CVE"] = "".join(cve)
        output_string["CVSS"] = ''.join(cvss)
        output_string["Referencias"] = ''.join(referencias)[:-1]
    else:
        output_string["Traduccion"] = "_UPS_"
    #print(str(output_string) + "\n")
    spanish_info.clear()
    return output_string

def read_parsed_csv_by_traducction(filename,traducction_status):
    fieldnames = ('Nombre_de_Vulnerabilidad', 'NessusID', 'CVE', 'CVSS','Prioridad','Severidad','IP','Hostname', 'Protocolo',
                  'Puerto','Plataforma','Descripcion','Solucion','Familia_de_Plugins','Nombre_de_Plugin','Tipo_de_Servicio','Categoria',"Referencias",
                  'Traduccion')
    data = []

    parsed_file = csv.DictReader(filename,fieldnames=fieldnames)
    headers = dict( (n,n) for n in fieldnames )
    for row in parsed_file:
        if row["Traduccion"] == traducction_status:
            data.append(dict(row))
    return data

def write_non_translated(file,data,files_num):

    fieldnames = ('NessusID', 'QualysID', 'AcunetixID','Nombre_de_Vulnerabilidad', 'Descripcion','Solucion','Workaround','Categoria',
                  'Efecto', 'Prioridad', 'CVSS', 'Plataforma', 'Subplataforma','CVE', 'Referencias','Exploit','Estado',
                  'Patrones','Revisada','Severidad')

    writer = csv.DictWriter(file, fieldnames=fieldnames)
    headers = dict( (n,n) for n in fieldnames )
    #print(headers.__str__())
    #print(str(data))
    if (files_num == 1):
        writer.writerow(headers)
    for row in data:
        ri = headers.copy()
        ri.clear()
        if ("severity" in row):
            for f in headers:
                if f in row:
                    ri[f] = row[f]
            writer.writerow(ri)
        #print(row)
    data.clear()

def borrar_archivos_directorio(directorio="./tmp/"):

    tmp_files = os.listdir(directorio)
    for f in tmp_files:
        try:
            os.remove(directorio + f)
        except (OSError, IOError) as e:
            print("ERROR: " + str(e.errno))

if __name__ == "__main__":
    files = []
    vulns = []
    cont = 1
    files = read_dir_files()
    print(str(len(files)) + " Archivos encontrados")
    borrar_archivos_directorio()
    borrar_archivos_directorio(directorio="./out/")
    for f in files:
        file_info = []
        print("----------Analizando archivo " + str(cont) + "----------->" + f)
        vulns = get_xml_info(f)
        #print(str(vulns))
        #Se abre el archivo CSV que se escribira
        fp1 = open_csv_file("out",".apg","wt")
        print("Procesando " + str(vulns.__len__()) + " registros..." )
        for v in vulns:
            reportData = {}
            #print(get_spanish_info_by_nessusid(v["pluginID"]))
            #print(str(v))
            reportData.update( merge_info(v,get_spanish_info_by_nessusid(v["pluginID"])))
            file_info.append(reportData)
            #print(str(reportData))
        reportData.clear()
        #print(str(file_info))
        #Se escribe el contenido del archivo
        #print(reportdata.keys())
        write_csv_parsed_file(fp1,file_info,cont)
        #Se cierra el CSV creado y limpiamos variables
        close_csv_file(fp1)
        vulns.clear()
        file_info.clear()

        #LEEMOS EL ARCHIVO PARSEADO
        fp1 = open_csv_file("out",".apg","rt")

        #obtenelos los registros traducidos y los no traducidos
        non_translated = read_parsed_csv_by_traducction(fp1,"_UPS_")

    #if len(non_translated) == 0:
        #Creamos el archivo con las traducciones
        fp2 = open_csv_file("out_translated",".atg","at", dir="./out")
        fp1.seek(0)
        translated = read_parsed_csv_by_traducction(fp1,"OK")
        #Escribimos a los archivos correspondientes
        write_csv_parsed_file(fp2,translated, cont)
        close_csv_file(fp2)
        translated.clear()
        print("Hecho.")
    #else :
        #Creamos el archivo con las traducciones no encontradas
        fp3 = open_csv_file("out_non_translated",".tne","at",dir="./out")
        write_non_translated(fp3,non_translated,cont)
        close_csv_file(fp3)
        print("¡¡¡ADVERTENCIA !!! - Existen traducciones NO ENCONTRADAS, por favor siga los siguientes pasos:\n"
          "1.- Verifique los archivos \".tne\" del directorio ./out.\n"
          "2.- Edite los archivos generados con las traducciones faltantes.\n"
          "3.- Utilice el programa vuln_loader.py para cargar las nuevas traducciones.\n"
          "4.- Vuelva a ejecutar " + sys.argv[0] + " hasta que no salga esta advertencia.\n")

        #Cerramos los archivos y limpiamos variables
        non_translated.clear()
        close_csv_file(fp1)
        cont = cont + 1
    #borrar_archivos_directorio()
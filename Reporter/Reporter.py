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


import sys

sys.path.append('lib/')

import ipcalc
import getopt
from gcs.reportdata import *
from gcs.reportformat import *


def write_tech_report(archivo,seg_list):

    ###
    # ALTAS
    ###
    reporte = crear_reporte_odt()

    #crear_texto_generico(reporte)
    #Creamos la tabla de IP /Segmento
    ip_hostname_list = []
    ip_hostname_list  = [ get_ip_hostname_list(s)  for s in seg_list]
    ip_hostname_list =[ i for s in ip_hostname_list for i in s]

    crear_tabla_ip_hostname(reporte,
                            "Direciones IP del Reporte",
                            ip_hostname_list)

    for segmento in seg_list:
        #Se obtiene la informacion completa por prioridad ALTA
        vuln_info = get_info_vuln_by_priority(segmento,Priority.HIGH)
        #Obtengo los nessusid de  vulnerabilidades con prioridad ALTA y se escriben en el reporte
        vuln_list = get_vuln_list_by_priority(vuln_info,Priority.HIGH)
        tit = P(stylename="Seccion Title 12",text=unicode_string("ALTAS SEGMENTO: ") + str(segmento.network())+"/" +str(segmento.subnet()) )
        reporte.text.addElement(tit)
        reporte = write_seccion_report_by_priority(reporte, vuln_list, vuln_info)

        guardar_reporte_odf(reporte,"out/Reporte_Tecnico-ALTAS")

    ###
    # MEDIAS
    ###

    reporte = crear_reporte_odt()

    #crear_texto_generico(reporte)
    #Creamos la tabla de IP /Segmento
    ip_hostname_list = []
    ip_hostname_list  = [ get_ip_hostname_list(s)  for s in seg_list]
    ip_hostname_list =[ i for s in ip_hostname_list for i in s]

    crear_tabla_ip_hostname(reporte,
                            "Direciones IP del Reporte",
                            ip_hostname_list)

    for segmento in seg_list:
        #Se obtiene la informacion completa por prioridad MEDIA
        vuln_info = get_info_vuln_by_priority(segmento,Priority.MEDIUM)
        #Obtengo los nessusid de  vulnerabilidades con prioridad ALTA y se escriben en el reporte
        vuln_list = get_vuln_list_by_priority(vuln_info,Priority.MEDIUM)
        tit = P(stylename="Seccion Title 12",text=unicode_string("MEDIAS SEGMENTO: ") + str(segmento.network())+"/" +str(segmento.subnet()) )
        reporte.text.addElement(tit)
        reporte = write_seccion_report_by_priority(reporte, vuln_list, vuln_info)
        guardar_reporte_odf(reporte,"out/Reporte_Tecnico-MEDIAS")

    ###
    # BAJAS
    ###

    reporte = crear_reporte_odt()

    #crear_texto_generico(reporte)
    #Creamos la tabla de IP /Segmento
    ip_hostname_list = []
    ip_hostname_list  = [ get_ip_hostname_list(s)  for s in seg_list]
    ip_hostname_list =[ i for s in ip_hostname_list for i in s]

    crear_tabla_ip_hostname(reporte,
                            "Direciones IP del Reporte",
                            ip_hostname_list)

    for segmento in seg_list:
        #Se obtiene la informacion completa por prioridad MEDIA
        vuln_info = get_info_vuln_by_priority(segmento,Priority.LOW)
        #Obtengo los nessusid de  vulnerabilidades con prioridad ALTA y se escriben en el reporte
        vuln_list = get_vuln_list_by_priority(vuln_info,Priority.LOW)
        tit = P(stylename="Seccion Title 12",text=unicode_string("BAJAS SEGMENTO: ") + str(segmento.network())+"/" +str(segmento.subnet()) )
        reporte.text.addElement(tit)
        reporte = write_seccion_report_by_priority(reporte, vuln_list, vuln_info)
        guardar_reporte_odf(reporte,"out/Reporte_Tecnico-BAJAS")





def write_tech_report2(archivo,seg_list):
    ###
    # ALTAS
    ###
    reporte = crear_reporte_odt()

    #crear_texto_generico(reporte)
    #Creamos la tabla de IP /Segmento
    ip_hostname_list = []
    ip_hostname_list  = [ get_ip_hostname_list(s)  for s in seg_list]
    ip_hostname_list =[ i for s in ip_hostname_list for i in s]

    crear_tabla_ip_hostname(reporte,
                            "Direciones IP del Reporte",
                            ip_hostname_list)

    for segmento in seg_list:
        #Se obtiene la informacion completa por prioridad ALTA
        vuln_info = get_info_vuln_by_priority(segmento,Priority.HIGH)
        #Obtengo los nessusid de  vulnerabilidades con prioridad ALTA y se escriben en el reporte
        vuln_list = get_vuln_list_by_priority(vuln_info,Priority.HIGH)
        tit = P(stylename="Seccion Title 12",text=unicode_string("ALTAS SEGMENTO: ") + str(segmento.network())+"/" +str(segmento.subnet()) )
        reporte.text.addElement(tit)
        reporte = write_seccion_report_by_priority(reporte, vuln_list, vuln_info)

        ###
        # MEDIAS
        ###


        #Se obtiene la informacion completa por prioridad MEDIA
        vuln_info = get_info_vuln_by_priority(segmento,Priority.MEDIUM)
        #Obtengo los nessusid de  vulnerabilidades con prioridad ALTA y se escriben en el reporte
        vuln_list = get_vuln_list_by_priority(vuln_info,Priority.MEDIUM)
        tit = P(stylename="Seccion Title 12",text=unicode_string("MEDIAS SEGMENTO: ") + str(segmento.network())+"/" +str(segmento.subnet()) )
        reporte.text.addElement(tit)
        reporte = write_seccion_report_by_priority(reporte, vuln_list, vuln_info)

        ###
        # BAJAS
        ###

        #Se obtiene la informacion completa por prioridad MEDIA
        vuln_info = get_info_vuln_by_priority(segmento,Priority.LOW)
        #Obtengo los nessusid de  vulnerabilidades con prioridad ALTA y se escriben en el reporte
        vuln_list = get_vuln_list_by_priority(vuln_info,Priority.LOW)
        tit = P(stylename="Seccion Title 12",text=unicode_string("BAJAS SEGMENTO: ") + str(segmento.network())+"/" +str(segmento.subnet()) )
        reporte.text.addElement(tit)
        reporte = write_seccion_report_by_priority(reporte, vuln_list, vuln_info)

        guardar_reporte_odf(reporte,"out/Reporte_Tecnico-TODAS")


def write_exe_report(archivo, seg_list):
    reporte = crear_reporte_odt()
    #crear_texto_generico(reporte)
    #crear_bd_temporal(archivo)
    all_high = 0
    all_medium = 0
    all_low = 0

    for segmento in seg_list:
        #Se obtiene la informacion completa por prioridad ALTA
        vuln_info_high = get_info_vuln_by_priority(segmento,Priority.HIGH)
        #Obtengo los nessusid de  vulnerabilidades con prioridad ALTA y se escriben en el reporte
        vuln_list_high = get_vuln_list_by_priority(vuln_info_high,Priority.HIGH)

        #Se obtiene la informacion completa por prioridad MEDIA
        vuln_info_medium = get_info_vuln_by_priority(segmento,Priority.MEDIUM)
        #ip_list = get_ip_high_vuln(segmento,Priority.MEDIUM)
        ip_list = get_ip_list_by_priority(segmento,Priority.HIGH)
        #vuln_info_medium = clean_no_high_vulns(ip_list,vuln_info_medium)
        #Obtengo los nessusid de  vulnerabilidades con prioridad MEDIA y se escriben en el reporte
        vuln_list_medium = get_vuln_list_by_priority(vuln_info_medium,Priority.MEDIUM)

        #Se obtiene la informacion completa por prioridad BAJA
        vuln_info_low = get_info_vuln_by_priority(segmento,Priority.LOW)
        #ip_list = get_ip_high_vuln(segmento,Priority.LOW)
        ip_list = get_ip_list_by_priority(segmento,Priority.HIGH)
        #vuln_info_low = clean_no_high_vulns(ip_list,vuln_info_low)
        #Obtengo los nessusid de  vulnerabilidades con prioridad BAJA y se escriben en el reporte
        vuln_list_low = get_vuln_list_by_priority(vuln_info_low,Priority.LOW)

        tdata = {"Altas":len(vuln_list_high),
                 "Medias":len(vuln_list_medium),
                 'Bajas': len(vuln_list_low)}

        all_high = all_high + len(vuln_list_high)
        all_medium = all_medium + len(vuln_list_medium)
        all_low = all_low + len(vuln_list_low)


        graficar_totales_por_segmento(reporte,segmento,tdata,graph_file_name="out/img/vbarchart-" + str(segmento.network()) +
                                                                             "-" + str(segmento.subnet()) + ".png")

        cat_list = get_category_list_by_priority(segmento,Priority.HIGH)
        cat_list = [unicode_string(x) for x in cat_list]
        totals = get_vuln_category_total(vuln_list_high,cat_list)
        graficar_totales_por_criticidad_en_segmento(reporte,segmento,totals,Priority.HIGH,graph_file_name="out/img/cchartH-"+ str(segmento.network()) +
                                                                             "-" + str(segmento.subnet()) + ".png")

        cat_list = get_category_list_by_priority(segmento,Priority.MEDIUM)
        cat_list = [unicode_string(x) for x in cat_list]
        totals = get_vuln_category_total(vuln_list_medium,cat_list)
        graficar_totales_por_criticidad_en_segmento(reporte,segmento,totals,Priority.MEDIUM,graph_file_name="out/img/cchartM-"+ str(segmento.network()) +
                                                                             "-" + str(segmento.subnet()) + ".png")

        cat_list = get_category_list_by_priority(segmento,Priority.LOW)
        cat_list = [unicode_string(x) for x in cat_list]
        totals = get_vuln_category_total(vuln_list_low,cat_list)
        graficar_totales_por_criticidad_en_segmento(reporte,segmento,totals,Priority.LOW,graph_file_name="out/img/cchartL-"+ str(segmento.network()) +
                                                                             "-" + str(segmento.subnet()) + ".png")

        #Creamos la tabla de IP /Segmento
        #ip_hostname_list = get_ip_hostname_list(segmento)
        #crear_tabla_ip_hostname(reporte,
        #                        str(segmento.network())+"/" +str(segmento.subnet()),
        #                        ip_hostname_list)

    #####
    ## TODAS
    ####
    tdata = {"Altas":all_high,
                 "Medias":all_medium,
                 'Bajas': all_low}
    graficar_totales_por_segmento(reporte,segmento,tdata,graph_file_name="out/img/vbarchart-TOTALES.png")


    ip_hostname_list  = [ get_ip_hostname_list(s)  for s in seg_list]
    ip_hostname_list =[ i for s in ip_hostname_list for i in s]
    crear_tabla_ip_hostname(reporte,
                                "Direciones IP del Reporte",
                                ip_hostname_list)

    guardar_reporte_odf(reporte,"out/Reporte_Ejecutivo")



def write_technical_report(archivo, segmento):

    reporte = crear_reporte_odt()


    #crear_texto_generico(reporte)
    #crear_bd_temporal(archivo)

    #Creamos la tabla de IP /Segmento
    ip_hostname_list = get_ip_hostname_list(segmento)
    #ip_hostname_list = get_ip_high_vuln(segmento,Priority.HIGH)
    crear_tabla_ip_hostname(reporte,
                            str(segmento.network())+"/" +str(segmento.subnet()),
                            ip_hostname_list)

    #Se obtiene la informacion completa por prioridad ALTA
    vuln_info = get_info_vuln_by_priority(segmento,Priority.HIGH)
    #Obtengo los nessusid de  vulnerabilidades con prioridad ALTA y se escriben en el reporte
    vuln_list = get_vuln_list_by_priority(vuln_info,Priority.HIGH)
    tit = P(stylename="Seccion Title 12",text=unicode_string("ALTAS"))
    reporte.text.addElement(tit)
    reporte = write_seccion_report_by_priority(reporte, vuln_list, vuln_info)


    #Se obtiene la informacion completa por prioridad MEDIA
    vuln_info = get_info_vuln_by_priority(segmento,Priority.MEDIUM)
    #ip_list = get_ip_high_vuln(segmento,Priority.MEDIUM)
    ip_list = get_ip_list_by_priority(segmento,Priority.HIGH)
    #vuln_info = clean_no_high_vulns(ip_list,vuln_info)
    #Obtengo los nessusid de  vulnerabilidades con prioridad MEDIA y se escriben en el reporte
    vuln_list = get_vuln_list_by_priority(vuln_info,Priority.MEDIUM)
    tit = P(stylename="Seccion Title 12",text=unicode_string("MEDIAS"))
    reporte.text.addElement(tit)
    reporte = write_seccion_report_by_priority(reporte, vuln_list, vuln_info)

    #Se obtiene la informacion completa por prioridad BAJA
    vuln_info = get_info_vuln_by_priority(segmento,Priority.LOW)
    #ip_list = get_ip_high_vuln(segmento,Priority.LOW)
    ip_list = get_ip_list_by_priority(segmento,Priority.HIGH)
    #vuln_info = clean_no_high_vulns(ip_list,vuln_info)
    #Obtengo los nessusid de  vulnerabilidades con prioridad BAJA y se escriben en el reporte
    vuln_list = get_vuln_list_by_priority(vuln_info,Priority.LOW)
    tit = P(stylename="Seccion Title 12",text=unicode_string("BAJAS"))
    reporte.text.addElement(tit)
    reporte = write_seccion_report_by_priority(reporte, vuln_list, vuln_info)


    guardar_reporte_odf(reporte,"out/Reporte_Tecnico-" + str(segmento.network()) + "-" + str(segmento.subnet()))

def write_executive_report(archivo, segmento):

    reporte = crear_reporte_odt()
    crear_texto_generico(reporte)
    #crear_bd_temporal(archivo)
    #Se obtiene la informacion completa por prioridad ALTA
    vuln_info_high = get_info_vuln_by_priority(segmento,Priority.HIGH)
    #Obtengo los nessusid de  vulnerabilidades con prioridad ALTA y se escriben en el reporte
    vuln_list_high = get_vuln_list_by_priority(vuln_info_high,Priority.HIGH)

    #Se obtiene la informacion completa por prioridad MEDIA
    vuln_info_medium = get_info_vuln_by_priority(segmento,Priority.MEDIUM)
    #ip_list = get_ip_high_vuln(segmento,Priority.MEDIUM)
    ip_list = get_ip_list_by_priority(segmento,Priority.HIGH)
    #vuln_info_medium = clean_no_high_vulns(ip_list,vuln_info_medium)
    #Obtengo los nessusid de  vulnerabilidades con prioridad MEDIA y se escriben en el reporte
    vuln_list_medium = get_vuln_list_by_priority(vuln_info_medium,Priority.MEDIUM)

    #Se obtiene la informacion completa por prioridad BAJA
    vuln_info_low = get_info_vuln_by_priority(segmento,Priority.LOW)
    #ip_list = get_ip_high_vuln(segmento,Priority.LOW)
    ip_list = get_ip_list_by_priority(segmento,Priority.HIGH)
    #vuln_info_low = clean_no_high_vulns(ip_list,vuln_info_low)
    #Obtengo los nessusid de  vulnerabilidades con prioridad BAJA y se escriben en el reporte
    vuln_list_low = get_vuln_list_by_priority(vuln_info_low,Priority.LOW)

    tdata = {"Altas":len(vuln_list_high),
             "Medias":len(vuln_list_medium),
             'Bajas': len(vuln_list_low)}

    graficar_totales_por_segmento(reporte,segmento,tdata,graph_file_name="out/img/vbarchart-" + str(segmento.network()) +
                                                                         "-" + str(segmento.subnet()) + ".png")

    cat_list = get_category_list_by_priority(segmento,Priority.HIGH)
    cat_list = [unicode_string(x) for x in cat_list]
    totals = get_vuln_category_total(vuln_list_high,cat_list)
    graficar_totales_por_criticidad_en_segmento(reporte,segmento,totals,Priority.HIGH,graph_file_name="out/img/cchartH-"+ str(segmento.network()) +
                                                                         "-" + str(segmento.subnet()) + ".png")

    cat_list = get_category_list_by_priority(segmento,Priority.MEDIUM)
    cat_list = [unicode_string(x) for x in cat_list]
    totals = get_vuln_category_total(vuln_list_medium,cat_list)
    graficar_totales_por_criticidad_en_segmento(reporte,segmento,totals,Priority.MEDIUM,graph_file_name="out/img/cchartM-"+ str(segmento.network()) +
                                                                         "-" + str(segmento.subnet()) + ".png")

    cat_list = get_category_list_by_priority(segmento,Priority.LOW)
    cat_list = [unicode_string(x) for x in cat_list]
    totals = get_vuln_category_total(vuln_list_low,cat_list)
    graficar_totales_por_criticidad_en_segmento(reporte,segmento,totals,Priority.LOW,graph_file_name="out/img/cchartL-"+ str(segmento.network()) +
                                                                         "-" + str(segmento.subnet()) + ".png")

    #Creamos la tabla de IP /Segmento

    ip_hostname_list = get_ip_hostname_list(segmento)
    crear_tabla_ip_hostname(reporte,
                            str(segmento.network())+"/" +str(segmento.subnet()),
                            ip_hostname_list)

    guardar_reporte_odf(reporte,"out/Reporte_Ejecutivo-" + str(segmento.network()) + "-" + str(segmento.subnet()))

def write_lack_of_updates(archivo, segmento):

    reporte = crear_reporte_odt()
    crear_texto_generico(reporte)
    #crear_bd_temporal(archivo)

    #Creamos la tabla de IP /Segmento
    ip_hostname_list = get_ip_hostname_list(segmento)
    #ip_hostname_list = get_ip_high_vuln(segmento,Priority.HIGH)
    crear_tabla_ip_hostname(reporte,
                            str(segmento.network())+"/" +str(segmento.subnet()),
                            ip_hostname_list)

    #Actualizaciones ALTAS
    lack_updates = get_lack_updates(segmento,Priority.HIGH)

    #for l in lack_updates:
    #   print(str(l))

    crear_tabla_vulnerabilidades(reporte,"Actualizaciones de prioridad ALTA - Segmento" + str(segmento.network()) + "-" + str(segmento.subnet()),lack_updates, Priority.HIGH)

    #Actualizaciones MEDIAS
    lack_updates = get_lack_updates(segmento,Priority.MEDIUM)
    crear_tabla_vulnerabilidades(reporte,"Actualizaciones de prioridad MEDIA - Segmento" + str(segmento.network()) + "-" + str(segmento.subnet()),lack_updates,  Priority.MEDIUM)

    #Actualizaciones BAJAS
    lack_updates = get_lack_updates(segmento,Priority.LOW)
    crear_tabla_vulnerabilidades(reporte,"Actualizaciones de prioridad BAJA - Segmento" + str(segmento.network()) + "-" + str(segmento.subnet()),lack_updates,  Priority.LOW)

    guardar_reporte_odf(reporte,"out/Reporte_Falta_actualizaciones-" + str(segmento.network()) + "-" + str(segmento.subnet()))

def write_lack_of_updates2(archivo, seg_list):

    reporte = crear_reporte_odt()
    #crear_texto_generico(reporte)
    #crear_bd_temporal(archivo)

    for segmento in seg_list:

        #Creamos la tabla de IP /Segmento
        ip_hostname_list = get_ip_hostname_list(segmento)
        #ip_hostname_list = get_ip_high_vuln(segmento,Priority.HIGH)
        crear_tabla_ip_hostname(reporte,
                            str(segmento.network())+"/" +str(segmento.subnet()),
                            ip_hostname_list)

        #Actualizaciones ALTAS
        lack_updates = get_lack_updates(segmento,Priority.HIGH)
        crear_tabla_vulnerabilidades(reporte,"Actualizaciones de prioridad ALTA - Segmento" + str(segmento.network()) + "-" + str(segmento.subnet()),lack_updates, Priority.HIGH)

        #Actualizaciones MEDIAS
        lack_updates = get_lack_updates(segmento,Priority.MEDIUM)
        crear_tabla_vulnerabilidades(reporte,"Actualizaciones de prioridad MEDIA - Segmento" + str(segmento.network()) + "-" + str(segmento.subnet()),lack_updates,  Priority.MEDIUM)

        #Actualizaciones BAJAS
        lack_updates = get_lack_updates(segmento,Priority.LOW)
        crear_tabla_vulnerabilidades(reporte,"Actualizaciones de prioridad BAJA - Segmento" + str(segmento.network()) + "-" + str(segmento.subnet()),lack_updates,  Priority.LOW)

    guardar_reporte_odf(reporte,"out/Reporte_Falta_actualizaciones")

def usage():
    print("Verifique el numero de argumentos.")



if __name__ == "__main__":
    Priority = enum('NONE','LOW','MEDIUM','HIGH')

    try:
        opt, args = getopt.getopt(sys.argv[1:], "i:f:s:", ["archivo=","file=","segmento="])
    except getopt.GetoptError as err:
        # print help information and exit:
        #usage()
        print str(err)
        sys.exit(2)

    seg_list = []
    for o,a in opt:
        if o in ('-i','-f','--archivo','--file'):
            archivo = a
        elif o in ('-s','--segmento'):
            arg_seg_list = a.split(',')
            seg_list = [ipcalc.Network(s.split('/')[0], s.split('/')[1]) for s in arg_seg_list ]

    crear_bd_temporal(archivo)

    if seg_list == []:
        ip_list = get_all_ip_list()
        ips = [i for o in ip_list for i in o]
        seg_list = [ipcalc.Network(s.split('/')[0], s.split('/')[1])for s in getNetwork(ips)]
    #print(len(seg_list))
    #print(seg_list)

    write_tech_report(archivo,seg_list)
    write_tech_report2(archivo,seg_list)
    write_exe_report(archivo,seg_list)
    write_lack_of_updates2(archivo,seg_list)

    print("Hecho.")

    '''
    if seg_list != []:
        for s in seg_list:

            write_technical_report(archivo,s)
            write_executive_report(archivo,s)
            write_lack_of_updates(archivo,s)

            write_technical_report(archivo)
            eliminar_bd_temporal()
            #print(str(s))
        print("Hecho.")
    else:
        usage()
    '''
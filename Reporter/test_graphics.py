import matplotlib.pyplot
import math


def dibujar_grafica_pastel(labels, values, title, colors=None):

    if len(labels) == len(values):
        for l in labels:
            graph_labels = tuple(labels)
            graph_values = list(values)

        if colors != None and len(colors) == len(labels):
            colors = list(colors)
        patches, texts, values1 = matplotlib.pyplot.pie(values, colors=colors, shadow=True, startangle=90, radius=1, autopct='%1.1f%%' )

        labels = ['{0} - {1:} '.format(i,j) for i,j in zip(graph_labels, graph_values)]
        sort_legend = True

        if sort_legend:
            patches, labels, dummy =  zip(*sorted(zip(patches, labels, values),
                                                  key=lambda x: x[2],
                                                  reverse=True))
        matplotlib.pyplot.legend(patches, labels, loc='upper left', bbox_to_anchor=(-0.1, 1.),
                                 fontsize=10)
        matplotlib.pyplot.title(title)
        matplotlib.pyplot.savefig('piechart.png', bbox_inches='tight')
        #matplotlib.pyplot.show()
    else:
        print("Error en los argumentos, den de ser iguales")

def dibujar_grafica_barras_horizontales(labels, values, title, colors=None):

    if len(labels) == len(values):

        if colors != None and len(colors) == len(labels):
            colors = tuple(colors)

        graph_labels = tuple(labels)
        graph_labels_size = range(len(list(labels)))
        graph_values = tuple(values)


        x_size = max(values) * 0.1 + max(values)

        patches = matplotlib.pyplot.barh(graph_labels_size,graph_values , align='center', alpha=1.0, color=colors)
        matplotlib.pyplot.yticks(graph_labels_size,labels)

        sizes = []
        for c in range(len(patches)):
            sizes.append( graph_labels[c] + "(" + str(patches[c].get_width()) + ")" )

        matplotlib.pyplot.xlim(xmax=x_size)
        matplotlib.pyplot.xlabel("Numero de Vulnerabilidades")
        #matplotlib.pyplot.xticks()

        matplotlib.pyplot.title(title)
        matplotlib.pyplot.legend(patches, sizes, loc='upper right', bbox_to_anchor=(1.3, 1.0),
                                     fontsize=10, shadow="true")
        matplotlib.pyplot.savefig('hbarchart.png', bbox_inches='tight')
        #matplotlib.pyplot.show()
    else:
        print("Error en los argumentos, den de ser iguales")

def dibujar_grafica_barras_verticales(labels, values, title, colors=None):

    x = range(len(values))

    y_size = max(values) * 0.1 + max(values)
    graph_values = tuple(values)
    graph_labels  = tuple(labels)

    #fig, ax = matplotlib.pyplot.subplots()
    patches = matplotlib.pyplot.bar(x,graph_values, color=colors )

    #sizes = []
    #for c in range(len(patches)):
    #    print(str(patches))
    #    sizes.append( graph_labels[c] + "(" + str(patches[c].get_height()) + ")" )

    sizes = [ graph_labels[c] + "(" + str(patches[c].get_height()) + ")"
                 for c in range(len(patches)) ]

    x_label_pos = [y+0.4 for y in x ]
    matplotlib.pyplot.xlim(xmin=-0.2)
    matplotlib.pyplot.xticks(x_label_pos, graph_labels)
    matplotlib.pyplot.ylim(ymax=y_size)

    matplotlib.pyplot.title(title)
    matplotlib.pyplot.legend(patches, sizes, loc='upper right', bbox_to_anchor=(1.3, 1.0),
                                 fontsize=10, shadow="true")
    matplotlib.pyplot.savefig('vbarchart.png', bbox_inches='tight')
    #matplotlib.pyplot.show()


def my_autopct(pct,values):
    total=sum(values)
    val=int((pct*total/100.0)+0.5)
    return '{p:.2f}%  ({v:d})'.format(p=pct,v=val)


if __name__ == "__main__":
    values = [800,30,20,100]
    #labels=['Altas','Medias','Bajas','Informativas']
    #colors = ['red','lightskyblue','gold','yellowgreen']

    labels=['Altas','Medias','Bajas','Informativas']
    colors = ['red','lightskyblue','gold','green']


    dibujar_grafica_pastel(labels,values,"Vulnerabilidades por segmento X", colors)
    #dibujar_grafica_barras_verticales(labels,values,"Vulnerabilidades por segmento X", colors)
    #dibujar_grafica_barras_horizontales(labels,values,"Vulnerabilidades por segmento X", colors)
# Mitigación de riesgos de ciberseguridad utilizando microsegmentación

## Descripción

Este es el código utilizado en el caso de estudio del Trabajo de Fin de Grado. Consta de tres archivos:

<ul>
<li><b>microsegmentation.py</b>: En él se define una aplicación para un controlador Ryu que permite llevar a cabo una mitigación de riesgos de ciberseguridad mediante la microsegmentación dinámica de la red. La aplicación hace uso de un nivel de riesgo,cuyo valor es introducido a través de una API. El código está adaptado para el caso de estudio, como se explica en la memoria.</li>
<li><b>mininet-topologies/topology.py</b>: Se trata de la topología utilizada en el caso de estudio para su ejecución con mininet.</li>
<li><b>mininet-topologies/config</b>: Archivo de configuración de la topología.</li>
</ul>

## Prerrequisitos

En primer lugar, para la ejecución del código es necesario instalar Ryu. Se pueden encontrar los pasos para hacerlo en <a href=https://ryu.readthedocs.io/en/latest/getting_started.html>la documentación de Ryu</a>.

Además, se debe instalar también Mininet <a href=http://mininet.org/download/>siguiendo los pasos de su documentación</a>.

## Ejecución

Una vez descargado el proyecto e instalado el software necesario, se puede llevar a cabo la ejecución del programa:

1. Ejecutar la aplicación en el controlador Ryu:
   ```sh
   ryu-manager microsegmentation.py
   ``` 
2. Crear la red con mininet:
   ```sh
   sudo mn --custom mininet-topologies/topology_2.py --mac --pre mininet-topologies/config_3 --topo mytopo --controller=remote,ip=127.0.0.1,port=6633 --switch ovs,protocols=OpenFlow13
   ``` 
3. Visualización del nivel de riesgo a través de la API:
   ```sh
   curl http://localhost:8080/riskLevel
   ``` 
4. Modificación del nivel de riesgo a través de la API:
   ```sh
   curl -d riskLevel -X PUThttp://localhost:8080/riskLevel
   ```   
 Donde riskLevel puede tomar valores "0", "1", o "2".

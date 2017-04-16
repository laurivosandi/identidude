Teile on lisatud kasutajakonto!

Teile on lisatud asutuses {{ domain.description }} järgnev kasutajakonto, selle abil saate asutuse arvutites sisse logida.

Kasutajanimi: {{ username }}
Parool: {{ password }}

Palun vahetage parool kohe välja meie arvutipargi haldusliideses [1] ning kontrollige, et seal oleks korrektsed kontaktandmed. Sealt leiab ka täpsemad juhised kuidas kodusest arvutist võrgukettale ligi pääseda.

{% if local_helpdesk %}
Kui teil esineb tõrkeid arvutite kasutamisel palun pöörduge kohalik IT-tugiisiku {{local_helpdesk.name}} poole [2].{% endif %}

Kui teil on probleeme arvutisse sisselogimisega või esineb tõrkeid võrguketta kasutamisel võite otse pöörduda serveripargi hooldaja {{ server_helpdesk.name }} poole [3].

1. http://ldap.povi.ee/
2. {{ local_helpdesk.email }}
3. {{ server_helpdesk.email }}

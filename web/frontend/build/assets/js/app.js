const url = "http://localhost/api/dangerous_domains?fmt=json"
const tbodyElement = document.querySelector("tbody")

fetch(url)
  .then(data => data.json())
    .then(domains => {
        console.log(domains);
        insertDomainsIntoTable(domains);
    })

const insertDomainsIntoTable = domains => {
    for (const domain of domains) {
        if (domain.is_alive || domain.is_dangerous) {
            const newRow = document.createElement("tr");
            tbodyElement.appendChild(newRow);
            newRow.innerHTML = `
                <td>${domain.url}</td>
                <td>${domain.owner_name}</td>
                <td>${domain.registrar_name}</td>
                <td>${domain.abuse_email}</td>
            `;
        }
    }
}
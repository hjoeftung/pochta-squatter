const url = "http://localhost/api/dangerous_domains"
const tbodyElement = document.querySelector("tbody")
const lastUpdatedElement = document.getElementById("last-updated")

fetch(url)
  .then(data => data.json())
    .then(domains => {
        console.log(domains);
        insertDomainsIntoTable(domains);
        outputLastUpdated(domains);
    })

const insertDomainsIntoTable = domains => {
    domains.forEach((domain, index) => {
        domain.owner_name = !domain.owner_name ? "Неизвестен" : domain.owner_name
        domain.abuse_emails = !domain.abuse_emails ? "Неизвестна" : domain.abuse_emails
        const newRow = document.createElement("tr");
        tbodyElement.appendChild(newRow);
        newRow.innerHTML = `
            <td>${index + 1}</td>
            <td><a href="${domain.url}">${domain.url}</a></td>
            <td>${domain.registrar_name}</td>
            <td>${domain.abuse_emails}</td>
            <td>${domain.owner_name}</td>
        `;
    });
}

const outputLastUpdated = domains => {
    lastUpdatedElement.innerHTML += domains[0].last_updated
}
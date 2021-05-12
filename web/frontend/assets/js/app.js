const getDomainsUrl = "http://localhost/api/dangerous-urls";
const tbodyElement = document.querySelector("tbody");
const tableElement = document.querySelector("table")
const lastUpdatedElement = document.getElementById("last-updated");
const whitelistingModal = document.getElementById("confirmation-modal");
const confirmWhitelistingBtn = document.querySelector(".btn--success");
const rejectWhitelistingBtn = document.querySelector(".btn--passive");
let whitelistDomainUrl = "http://localhost/api/dangerous-urls";

fetch(getDomainsUrl)
  .then(data => data.json())
    .then(domains => {
        console.log(domains);
        insertDomainsIntoTable(domains);
        outputLastUpdated(domains);
    })

const createNonDangerousCheckbox = (url, domain_id) => {
    const nonDangerousCheckBox = document.createElement("td");
    nonDangerousCheckBox.innerHTML += '<input type="checkbox">';
    nonDangerousCheckBox.id = url;
    nonDangerousCheckBox.addEventListener("click", () => {
        whitelistingModal.dataset.domainId = domain_id;
        whitelistingModal.dataset.url = url;
        toggleModal();
    });
    return nonDangerousCheckBox;
}

const insertDomainsIntoTable = domains => {
    domains.forEach((domain, index) => {
        domain.owner_name = !domain.owner_name ? "Неизвестен" : domain.owner_name;
        domain.abuse_emails = !domain.abuse_emails ? "Неизвестна" : domain.abuse_emails;

        const newRow = document.createElement("tr");
        tbodyElement.appendChild(newRow);

        newRow.innerHTML += `
            <td>${index + 1}</td>
            <td><a href="${domain.url}">${domain.url}</a></td>
            <td>${domain.registrar_name}</td>
            <td>${domain.abuse_emails}</td>
            <td>${domain.owner_name}</td>
        `;

        const nonDangerousCheckBox = createNonDangerousCheckbox(
            domain.url, domain.domain_id
        );
        newRow.appendChild(nonDangerousCheckBox);
    });
}

const outputLastUpdated = domains => {
    if (domains.length > 0) {
        lastUpdatedElement.innerHTML += domains[0].last_updated;
    } else {
        const today = new Date();
        const date = today.getDate() >= 10 ? today.getDate() : "0" + today.getDate().toString();
        const month = today.getMonth() + 1 >= 10
                        ? today.getMonth() + 1
                        : "0" + (today.getMonth() + 1).toString();
        const year = today.getFullYear();
        lastUpdatedElement.innerHTML += `${date}.${month}.${year}`;
    }
}

const toggleModal = () => {
    whitelistingModal.classList.toggle("visible");
}

const deleteWhitelistedRow = url => {
    console.log(url);
    const urlTableCell = document.getElementById(url);
    const rowIndex = urlTableCell.closest("tr").rowIndex;
    console.log(rowIndex);
    tableElement.deleteRow(rowIndex);
}

confirmWhitelistingBtn.addEventListener("click", () => {
    const domainId = whitelistingModal.dataset.domainId;
    const url = whitelistingModal.dataset.url;
    try {
        fetch(`${whitelistDomainUrl}/${domainId}`, { method: 'PATCH' });
        deleteWhitelistedRow(url);
    } catch (err) {
        console.log(err);
    } finally {
        toggleModal();
    }
})
rejectWhitelistingBtn.addEventListener("click", toggleModal);

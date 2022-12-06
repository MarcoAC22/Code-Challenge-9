const mongoose = require("mongoose")

var breedsSchema = mongoose.Schema({
    current_page: Number,
    data: [
        {
            breed: String,
            country: String,
            origin: String,
            coat: String,
            pattern: String,
        },
    ],
    first_page_url: String,
    from: Number,
    last_page: Number,
    last_page_url: String,
    links: [
        {
            url: String,
            label: String,
            active: Boolean,
        },
    ],
    next_page_url: String,
    path: String,
    per_page: Number,
    prev_page_url: Number,
    to: Number,
    total: Number,
}, { strict: false });

module.exports = mongoose.model("Breeds", breedsSchema)
class Recaller {

    $recaller;

    constructor($recaller) {
        this.$recaller = $recaller;
    }

    id() {
        return this.$recaller.split('|')[0];
    }

    token() {
        return this.$recaller.split('|')[1];
    }

    hash() {
        return this.$recaller.split('|')[2];
    }

    valid() {
        return this.properString() && this.hasAllSegments();
    }

    properString() {
        return is_string(this.$recaller) && String.contains(this.$recaller, '|');
    }

    hasAllSegments() {
        let $segments = this.$recaller.split('|');

        return count($segments) === 3 && trim($segments[0]) !== '' && trim($segments[1]) !== '';
    }
}

module.exports = Recaller
import { is_string, count, trim } from '@ostro/support/function';

/**
 * Class Recaller.
 */
class Recaller {
    public $recaller: any;

    /**
     * Create a new recaller instance.
     *
     * @param $recaller - Raw recaller string
     */
    constructor($recaller: any) {
        this.$recaller = $recaller;
    }

    /**
     * Get the user ID from the recaller string.
     *
     * @returns User ID segment
     */
    public id(): string {
        return this.$recaller.split('|')[0];
    }

    /**
     * Get the token from the recaller string.
     *
     * @returns Token segment
     */
    public token(): string {
        return this.$recaller.split('|')[1];
    }

    /**
     * Get the password hash from the recaller string.
     *
     * @returns Password hash segment
     */
    public hash(): string {
        return this.$recaller.split('|')[2];
    }

    /**
     * Determine if the recaller is valid.
     *
     * @returns True if properly formatted with all segments
     */
    public valid(): boolean {
        return this.properString() && this.hasAllSegments();
    }

    /**
     * Determine if the recaller is a valid string.
     *
     * @returns True if string contains a pipe separator
     */
    public properString(): boolean {
        return is_string(this.$recaller) && (String as any).contains(this.$recaller, '|');
    }

    /**
     * Determine if the recaller has all required segments.
     *
     * @returns True if 3 non-empty ID and token segments exist
     */
    public hasAllSegments(): boolean {
        const $segments = this.$recaller.split('|');

        return count($segments) === 3 && trim($segments[0]) !== '' && trim($segments[1]) !== '';
    }
}

export default Recaller;